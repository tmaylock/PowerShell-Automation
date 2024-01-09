
$global:checkpointurl = 'https://checkpointmanagementserver/web_api'
Function Get-CheckPointWebAPISession {
    $apikey = Get-SecretFromVault -Vault $global:Vault -Name 'checkpointapi' -AsPlainText
    $json = [PSCustomObject]@{
        'api-key' = $apikey
    } | ConvertTo-Json
    $uri = $checkpointurl + '/login'
    $global:checkpointsession = Invoke-RestMethod -Uri $uri -SkipCertificateCheck -Method Post -ContentType 'application/json' -Body $json
    return $checkpointsession
}

Function Invoke-CheckPointWebAPILogin {
   
    if ($null -eq $checkpointsession) {
        if ($Verbose) { Write-Host 'No CheckPoint session found, logging in...' }
        Get-CheckPointWebAPISession
    }
    else {

        [datetime]$lastlogon = $checkpointsession.'last-login-was-at'.'iso-8601'
        $logonexpiresat = $lastlogon.AddSeconds($checkpointsession.'session-timeout')

        if ($logonexpiresat -lt (Get-Date).AddSeconds(-30)) {
            if ($Verbose) { Write-Host 'CheckPoint session expired, logging in again...' }
            Get-CheckPointWebAPISession 
        }
        else {
            if ($Verbose) { Write-Host 'CheckPoint session available, skipping login...' }
            $checkpointsession
        }
    }
}

Function Get-CheckPointWebAPIData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $URL,
        [Parameter(Mandatory = $false)]
        [bool]
        $DebugData
    )
    begin {
        $checkpointsession = Invoke-CheckPointWebAPILogin
        $headers = @{}
        $headers.Add('X-chkp-sid', "$($checkpointsession.sid)")

        $data = @()
        $offset = 0
    }
    process {
       
        if ($DebugData) {
            $body = [PSCustomObject]@{
                'limit'         = 100
                'offset'        = $offset
                'details-level' = 'full'
            } | ConvertTo-Json
            $response = Invoke-RestMethod -Method Post -Headers $headers -Uri ($checkpointurl + "/$URL") -ContentType 'application/json' -SkipCertificateCheck -Body $body
            $data += $response.objects
        }
        else {

            do {
                $body = [PSCustomObject]@{
                    'limit'         = 500
                    'offset'        = $offset
                    'details-level' = 'full'
                } | ConvertTo-Json

                $response = Invoke-RestMethod -Method Post -Headers $headers -Uri ($checkpointurl + "/$URL") -ContentType 'application/json' -SkipCertificateCheck -Body $body
                $data += $response.objects

                $offset = $response.to
            }
            until (
                $response.to -eq $response.total
            )
        }

    }
    end {
        return $data
    }

}
  
    
Function Invoke-CheckPointWebAPILogout {

    if ($checkpointsession) {
        [datetime]$lastlogon = $checkpointsession.'last-login-was-at'.'iso-8601'
        $logonexpiresat = $lastlogon.AddSeconds($checkpointsession.'session-timeout')
        if ($logonexpiresat -gt (Get-Date)) {
            $headers = @{}
            $headers.Add('X-chkp-sid', "$($checkpointsession.sid)")
            $body = '{}'
            $uri = $checkpointurl + '/logout'
            Invoke-RestMethod -Uri $uri -SkipCertificateCheck -Method Post -ContentType 'application/json' -Headers $headers -Body $body | Out-Null
        }
    }
}

Function Get-CheckPointHosts {

    $hosts = Get-CheckPointWebAPIData -URL 'show-hosts'

    $properties = @(
        'uid',
        'name',
        @{Name = 'ip'; Expression = { $_.'ipv4-address' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $hosts | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table hosts -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}




Function Get-CheckPointHostsStatus {

    $query = @'
    SELECT  name, ip,uid
	FROM checkpoint.hosts
	where ip << '10.0.0.0/8' 
	and name !~* '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])' 
	and (name ~*'^.*(\.my)?\.domain\.com$' or name ~* '^((?!\.).)*$') 
'@

    $addresses = Invoke-PGSqlQuery -Type Select -Query $query

    $hosts_status = $addresses | ForEach-Object -ThrottleLimit 50 -Parallel {
        
        $pingable = if ([System.Net.NetworkInformation.Ping]::new().Send($_.ip, 3000).Status -eq 'Success') { $true } else { $false }
        try {
            $dns_ip = @([System.Net.Dns]::GetHostAddresses(($_.name)).IPAddressToString | Where-Object { $_ -like '10.*' })[0]
        }
        catch {
        }
        if ($_.ip -ne $dns_ip -and $null -ne $dns_ip -and $dns_ip -isnot [array]) {
            $dns_ip_pingable = if ([System.Net.NetworkInformation.Ping]::new().Send($dns_ip, 3000).Status -eq 'Success') { $true } else { $false }
        }

        [PSCustomObject]@{
            name            = $_.name
            ip              = $_.ip
            ip_pingable     = $pingable
            dns_ip          = $dns_ip
            dns_ip_pingable = $dns_ip_pingable
            uid             = $_.uid
        } 
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $hosts_status -Schema checkpoint -Table hosts_status -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-CheckPointNetworks {

    $Networks = Get-CheckPointWebAPIData -URL 'show-networks'

    $properties = @(
        'uid',
        'name',
        @{Name = 'subnet'; Expression = { $_.'subnet4' } },
        @{Name = 'subnet_mask'; Expression = { $_.'subnet-mask' } },
        @{Name = 'mask_length'; Expression = { $_.'mask-length4' } },
        'broadcast',
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $Networks | Select-Object -Property $properties
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table networks -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointGroups {

    $Groups = Get-CheckPointWebAPIData -URL 'show-groups'

    $properties = @(
        'uid',
        'name',
        @{Name = 'members'; Expression = { '{' + ($_.members -join ',') + '}' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $Groups | Select-Object -Property $properties
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table groups -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointAddressRanges {

    $AddressRanges = Get-CheckPointWebAPIData -URL 'show-address-ranges'

    $properties = @(
        'uid',
        'name',
        @{Name = 'ipv4_address_first'; Expression = { $_.'ipv4-address-first' } },
        @{Name = 'ipv4_address_last'; Expression = { $_.'ipv4-address-last' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $AddressRanges | Select-Object -Property $properties
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table address_ranges -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointMulticastAddressRanges {

    $MulticastAddressRanges = Get-CheckPointWebAPIData -URL 'show-multicast-address-ranges'

    $properties = @(
        'uid',
        'name',
        @{Name = 'ipv6_address_first'; Expression = { $_.'ipv6-address-first' } },
        @{Name = 'ipv6_address_last'; Expression = { $_.'ipv6-address-last' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $MulticastAddressRanges | Select-Object -Property $properties
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table multicast_address_ranges -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointGroupsWithExclusion {

    $GroupsWithExclusion = Get-CheckPointWebAPIData -URL 'show-groups-with-exclusion'

 
    $properties = @(
        'uid',
        'name',
        @{Name = 'include'; Expression = { '{' + ($_.include.uid -join ',') + '}' } },
        @{Name = 'except'; Expression = { '{' + ($_.except.uid -join ',') + '}' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $GroupsWithExclusion | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table groups_with_exclusion -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointServicesTCP {

    $ServicesTCP = Get-CheckPointWebAPIData -URL 'show-services-tcp'


    $properties = @(
        'uid',
        'name',
        'type',
        'port',
        @{Name = 'match_by_protocol_signature'; Expression = { $_.'match-by-protocol-signature' } },
        @{Name = 'override_default_settings'; Expression = { $_.'override-default-settings' } },
        @{Name = 'session_timeout'; Expression = { $_.'session-timeout' } },
        @{Name = 'use_default_session_timeout'; Expression = { $_.'use-default-session-timeout' } },
        @{Name = 'match_for_any'; Expression = { $_.'match-for-any' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } }
    )

    $inputobject = $ServicesTCP | Select-Object -Property $properties
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table services_tcp -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointServicesUDP {

    $ServicesUDP = Get-CheckPointWebAPIData -URL 'show-services-udp'

    $properties = @(
        'uid',
        'name',
        'type',
        'port',
        @{Name = 'match_by_protocol_signature'; Expression = { $_.'match-by-protocol-signature' } },
        @{Name = 'override_default_settings'; Expression = { $_.'override-default-settings' } },
        @{Name = 'session_timeout'; Expression = { $_.'session-timeout' } },
        @{Name = 'use_default_session_timeout'; Expression = { $_.'use-default-session-timeout' } },
        @{Name = 'match_for_any'; Expression = { $_.'match-for-any' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } }
    )

    $inputobject = $ServicesUDP | Select-Object -Property $properties
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table services_udp -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointServiceGroups {

    $ServiceGroups = Get-CheckPointWebAPIData -URL 'show-service-groups'

    $properties = @(
        'uid',
        'name',
        @{Name = 'members'; Expression = { '{' + ($_.members -join ',') + '}' } },
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } },
        'type'
    )

    $inputobject = $ServiceGroups | Select-Object -Property $properties
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table service_groups -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-CheckPointUnusedObjects {

    $UnusedObjects = Get-CheckPointWebAPIData -URL 'show-unused-objects'

    $properties = @(
        'uid',
        'name',
        'type',
        'comments',
        @{Name = 'last_modified'; Expression = { ([datetime]$_.'meta-info'.'last-modify-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'last_modifier'; Expression = { $_.'meta-info'.'last-modifier' } },
        @{Name = 'creation_time'; Expression = { ([datetime]$_.'meta-info'.'creation-time'.'iso-8601').ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } },
        @{Name = 'creator'; Expression = { $_.'meta-info'.'creator' } }
    )

    $inputobject = $UnusedObjects | Select-Object -Property $properties
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema checkpoint -Table unused_objects -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Invoke-CheckPointScheduledFunction {
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
            Write-Output 'Get-CheckPointHosts'; Get-CheckPointHosts
            Write-Output 'Get-CheckPointHostsStatus'; Get-CheckPointHostsStatus
            Write-Output 'Get-CheckPointNetworks'; Get-CheckPointNetworks
            Write-Output 'Get-CheckPointAddressRanges'; Get-CheckPointAddressRanges
            Write-Output 'Get-CheckPointMulticastAddressRanges'; Get-CheckPointMulticastAddressRanges
            Write-Output 'Get-CheckPointServicesTCP'; Get-CheckPointServicesTCP
            Write-Output 'Get-CheckPointServicesUDP'; Get-CheckPointServicesUDP
            Write-Output 'Get-CheckPointServiceGroups'; Get-CheckPointServiceGroups
            Write-Output 'Get-CheckPointUnusedObjects'; Get-CheckPointUnusedObjects

        }
    }
    Invoke-CheckPointWebAPILogout

}

