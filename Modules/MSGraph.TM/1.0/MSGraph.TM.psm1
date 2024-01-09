



Function Get-MSGraphDevices {

    Connect-MSGraph

    $devices = Get-MgDevice -All

    $properties = @(
        'AccountEnabled',
        @{Name = 'AdditionalProperties'; Expression = { $_.AdditionalProperties | ConvertTo-Json } }
        'ApproximateLastSignInDateTime',
        'ComplianceExpirationDateTime',
        'DeletedDateTime',
        'DeviceId',
        'DeviceVersion',
        'DisplayName',
        'Id',
        'IsCompliant',
        'IsManaged',
        'MdmAppId',
        'OnPremisesLastSyncDateTime',
        'OnPremisesSyncEnabled',
        'OperatingSystem',
        'OperatingSystemVersion',
        'PhysicalIds',
        'ProfileType',
        'SystemLabels',
        'TrustType')


    $inputobject = $devices | Select-Object -Property $properties -ExcludeProperty AdditionalProperties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'MSGraph' -Table 'devices' -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-MSGraphDirectoryAuditLogs {

  
    $1hourago = '{0:s}' -f (Get-Date).AddHours(-1) + 'Z'
    $AuditLogDirectoryAudit = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $1hourago" -All

    $properties = @(
        'id',
        'category',
        'correlationId',
        'result',
        'resultReason',
        'activityDisplayName',
        'activityDateTime',
        'loggedByService',
        'operationType',
        @{name = 'initiatedBy'; expression = { $_.initiatedBy | ConvertTo-Json -Depth 99 -Compress -WarningAction SilentlyContinue } },
        @{name = 'targetResources'; expression = { $_.targetResources | ConvertTo-Json -Depth 99 -Compress -WarningAction SilentlyContinue } },
        @{name = 'additionalDetails'; expression = { $_.additionalDetails | ConvertTo-Json -Depth 99 -Compress -WarningAction SilentlyContinue } }
    )

    try {

        $inputobject = $AuditLogDirectoryAudit | Select-Object -Property $properties
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'auditdirectorylogs' -Truncate $false
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-MSGraphNamedLocations {

   
    Connect-MSGraph
    $NamedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
    $cidr = $NamedLocations.Where({ $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' })

    [System.Collections.ArrayList]$networks = @()
    foreach ($network in $cidr) {
        $id = $network.id
        $displayname = $network.displayname
        $istrusted = $network.AdditionalProperties.isTrusted
        foreach ($cidraddress in $network.AdditionalProperties.ipRanges.cidrAddress) {
            [void]$networks.add([PSCustomObject]@{ id = $id; displayname = $displayname; istrusted = $istrusted; cidraddress = $cidraddress }) ;
        }
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $networks -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'ipnamedlocations' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-MSGraphRiskDetections {

    Connect-MSGraph

    $seconds = (Get-Date).Second
    $minutes = (Get-Date).Minute
    $date = (Get-Date).ToUniversalTime().AddHours(-1).AddMinutes(-$minutes).AddSeconds(-$seconds).ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')

    $riskdetections = Get-MgRiskDetection -Filter "lastUpdatedDateTime ge $date"

    if ($riskdetections) {
        $properties = @(
            'id',
            'risktype',
            'riskeventtype',
            'riskstate',
            'risklevel',
            'riskdetail',
            'source',
            'detectiontimingtype',
            'activity',
            'tokenissuertype',
            'ipaddress',
            'activitydatetime',
            'detecteddatetime',
            'lastupdateddatetime',
            'userid',
            'userdisplayname',
            'userprincipalname',
            'additionalinfo',
            @{name = 'location'; expression = { $_.location | ConvertTo-Json } }
        )

        $inputobject = $riskdetections | Select-Object -Property $properties
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'Office365' -Table 'riskdetections' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }

}
Function Get-MSGraphIntuneDevices {

    Connect-MSGraph

    $intunedevices = Get-MgDeviceManagementManagedDevice -All | Select-Object *, @{name = 'configurationmanagerclientenabledfeatures'; expression = { $_.configurationmanagerclientenabledfeatures | ConvertTo-Json -Compress } } -ExcludeProperty configurationmanagerclientenabledfeatures

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $intunedevices -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'intunemanageddevices' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-MSGraphIntuneComplianceTotals {


    $MSGraphIntuneCompliance_query = @'
    insert into "MSGraph".intune_compliance_totals
    select date,operatingsystem,osversion,compliancestate,sum(total) as total from (
    select  now()::date as date
    , operatingsystem
    , regexp_replace(osversion,'\.0$','') as osversion
    , compliancestate
    , count(*) as total
    FROM "MSGraph".intunemanageddevices
    group by  operatingsystem, osversion, compliancestate) totals
    group by date,operatingsystem,osversion,compliancestate
    on conflict (date,operatingsystem,osversion,compliancestate) DO UPDATE SET total=EXCLUDED.total;
'@       

    try {
        Invoke-PGSqlQuery -Type Select -Query $MSGraphIntuneCompliance_query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Restore-MSGraphOneDriveFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $UPN,
        [Parameter(Mandatory = $true)]
        [bool]
        $Restore
    )

    $LoginUrl = 'https://login.microsoft.com'
    $ResourceUrl = 'https://graph.microsoft.com'
    # Compose REST request.
    $Body = @{ grant_type = 'client_credentials'; resource = $ResourceUrl; client_id = $ClientID; client_secret = $ClientSecret }
    $OAuth = Invoke-RestMethod -Method Post -Uri $LoginUrl/$TenantName/oauth2/token?api-version=1.0 -Body $Body

    # Check if authentication is successfull.
    if ($null -eq $OAuth.access_token) {
        Write-Error 'No Access Token'
    }
    else {
        # Perform REST call.
        $HeaderParams = @{ 'Authorization' = "$($OAuth.token_type) $($OAuth.access_token)" }
    }


    $userid = (Invoke-PGSqlQuery -Type Select -Query "SELECT userprincipalname, id FROM `"Office365`".userid where userprincipalname ilike '$UPN%'").id.guid
    $useruri = "https://graph.microsoft.com/v1.0/users/$userid"

    $restoredate = (Get-Date).AddDays(-1)

    $drivesuri = "$useruri/drives"
    $drives = Get-MSGraphAPIData -ClientID $ClientID -TenantName $TenantName -ClientSecret $ClientSecret -Url $drivesuri
    $drives.value

    $driveid = ($drives.value)[0].id
    $childrenuri = "$useruri/drives/$driveid/items/root/children"
    $children = Get-MSGraphAPIData -ClientID $ClientID -TenantName $TenantName -ClientSecret $ClientSecret -Url $childrenuri

    $restorefiles = $children.value | Where-Object { $_.lastmodifieddatetime -gt $restoredate }
    $restorefiles | Select-Object id, lastmodifieddatetime, name, size
    
    foreach ($item in $restorefiles) {
        $versionsuri = "$useruri/drives/$driveid/items/$($item.id)/versions"
        $versions = (Get-MSGraphAPIData -ClientID $ClientID -TenantName $TenantName -ClientSecret $ClientSecret -Url $versionsuri).value
        $restoreversion = ($versions | Where-Object { $_.lastmodifieddatetime -lt $restoredate })[0]
        $restoreuri = "$useruri/drives/$driveid/items/$($item.id)/versions/$($restoreversion.id)/restoreVersion"
        if ($Restore) {
            Invoke-RestMethod -Method Post -Uri $restoreuri -Headers $HeaderParams
        }
    }

}

Function Get-MSGraphUserRegistrationDetails {

    Connect-MSGraph 

    $userRegistrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All


    $properties = @(
        'id',
        'userPrincipalName',
        'userDisplayName',
        'userType',
        'isAdmin',
        'isSsprRegistered',
        'isSsprEnabled',
        'isSsprCapable',
        'isMfaRegistered',
        'isMfaCapable',
        'isPasswordlessCapable',
        @{Name = 'methods'; Expression = { '{' + (($_.methodsRegistered) -join ',') + '}'  } }
        'defaultMfaMethod'
    )

    $inputobject = $userRegistrationDetails | Select-Object -Property $properties

    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'MSGraph' -Table 'userregistrationdetails' -OnConflict 'Do Nothing' -Truncate $true

}

Function Get-MSGraphGroups {

    Connect-MSGraph

    $groups = Get-MgGroup -All

    $properties = @(
        @{name = 'Classification'; expression = { $_.'Classification' } }
        @{name = 'Conversations'; expression = { $_.'Conversations' } }
        @{name = 'CreatedDateTime'; expression = { $_.'CreatedDateTime' } }
        @{name = 'DeletedDateTime'; expression = { $_.'DeletedDateTime' } }
        @{name = 'Description'; expression = { $_.'Description' } }
        @{name = 'DisplayName'; expression = { $_.'DisplayName' } }
        @{name = 'GroupTypes'; expression = { $_.'GroupTypes' } }
        @{name = 'Id'; expression = { $_.'Id' } }
        @{name = 'IsArchived'; expression = { $_.'IsArchived' } }
        @{name = 'Mail'; expression = { $_.'Mail' } }
        @{name = 'MailEnabled'; expression = { ($_.'MailEnabled' -eq $true) ?  ('True') : ('False') } }
        @{name = 'MailNickname'; expression = { $_.'MailNickname' } }
        @{name = 'ProxyAddresses'; expression = { $_.'ProxyAddresses' | ConvertTo-Json } }
        @{name = 'RenewedDateTime'; expression = { $_.'RenewedDateTime' } }
        @{name = 'SecurityEnabled'; expression = { ($_.'SecurityEnabled' -eq $true) ?  ('True') : ('False') } }
        @{name = 'SecurityIdentifier'; expression = { $_.'SecurityIdentifier' } }
        @{name = 'Visibility'; expression = { $_.'Visibility' } }
        @{name = 'AdditionalProperties'; expression = { $_.'AdditionalProperties' | ConvertTo-Json } })

        


    $inputobject = $groups | Select-Object -Property $properties -ExcludeProperty AdditionalProperties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'MSGraph' -Table 'groups' -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Invoke-MSGraphScheduledFunction {
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
            Write-Output 'Get-MSGraphIntuneDevices'; Get-MSGraphIntuneDevices
            Write-Output 'Get-MSGraphIntuneComplianceTotals'; Get-MSGraphIntuneComplianceTotals
            Write-Output 'Get-MSGraphRiskDetections'; Get-MSGraphRiskDetections
            Write-Output 'Get-MSGraphDirectoryAuditLogs'; Get-MSGraphDirectoryAuditLogs

        }
        'Daily' {
            Write-Output 'Get-MSGraphNamedLocations'; Get-MSGraphNamedLocations
            Write-Output 'Get-MSGraphUserRegistrationDetails'; Get-MSGraphUserRegistrationDetails
            Write-Output 'Get-MSGraphDevices'; Get-MSGraphDevices
            Write-Output 'Get-MSGraphGroups'; Get-MSGraphGroups
        }
    }

}