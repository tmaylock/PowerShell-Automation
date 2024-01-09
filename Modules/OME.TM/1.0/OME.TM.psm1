$omeserver = "omeserver"
Function Get-OMEData {
    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory)]
        [string]
        $Url,
  
        [Parameter(Mandatory = $false)]
        [string]
        $OdataFilter,
  
        [Parameter(Mandatory = $false)]
        [int]
        $MaxPages = $null
    )
    $Data = @()
    $NextLinkUrl = $null
    $CountData = Invoke-RestMethod -Uri $Url -Method Get -Credential (Get-OMECreds) -TimeoutSec 60
  

    if ($null -ne $CountData.'value') {
        $Data += $CountData.'value'
    }
    else {
        $Data += $CountData
    }
  
    if ($CountData.'@odata.nextLink') {
        $NextLinkUrl = "https://$omeserver$($CountData.'@odata.nextLink')"
    }

    $i = 1
    while ($NextLinkUrl) {
        if ($MaxPages) {
            if ($i -ge $MaxPages) {
                break
            }
            $i = $i + 1
        }
    
        $NextLinkData = Invoke-RestMethod -Uri "$($NextLinkUrl)" -Method Get -Credential (Get-OMECreds) 
        
        if ($null -ne $NextLinkData.'value') {
            $Data += $NextLinkData.'value'
        }
        else {
            $Data += $NextLinkData
        }    
    
        if ($NextLinkData.'@odata.nextLink') {
            $NextLinkUrl = "https://$omeserver$($NextLinkData.'@odata.nextLink')"
        }
        else {
            $NextLinkUrl = $null
        }
    }

    return $Data
}
 
Function Get-OMECreds {
    $scriptUser = 'ome_admin'
    $scriptPassword = Get-SecretFromVault -Vault $global:vault -Name OMEAdmin
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($scriptUser, $scriptPassword)
    return $creds
}

Function Get-OMEWarrantyInfo {
    $WarrantyInfo = Get-OMEData "https://$omeserver/api/WarrantyService/Warranties" | Select-Object *, @{name = 'DeviceName'; expression = { $_.DeviceName.Replace("$dns_suffix", '') } } -ExcludeProperty devicename
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $WarrantyInfo -OnConflict 'Do Nothing' -Schema 'ome' -Table 'warranties' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-OMEDevices {

    $Devices = @()
    $Devices += Get-OMEData "https://$omeserver/api/DeviceService/Devices"
    #$Devices | Add-Member -MemberType NoteProperty -Name Inventory -Value @()
    
  
    #$devicedata = $devices | ForEach-Object -ThrottleLimit 2 -Parallel {
    #    $device = $_
    #    $device.inventory = Get-OMEData "https://$using:omeserver/api/DeviceService/Devices($($Device.Id))/InventoryDetails" -ErrorAction SilentlyContinue | ConvertTo-Json -WarningAction SilentlyContinue
    #    $device
    #}

    $deviceinventory = $devices | ForEach-Object -ThrottleLimit 6 -Parallel {
        $device = $_

        $Properties = @(
            @{Name = 'id'; Expression = { $device.id } },
            'inventorytype',
            @{Name = 'inventoryinfo'; Expression = { $_.inventoryinfo | ConvertTo-Json -WarningAction SilentlyContinue } }
        )
        Get-OMEData "https://$using:omeserver/api/DeviceService/Devices($($Device.Id))/InventoryDetails" -ErrorAction SilentlyContinue | Select-Object -Property $Properties
    }
  
    $inputobject = $devices | Select-Object *, @{name = 'DeviceManagement'; expression = { $_.DeviceManagement | ConvertTo-Json -Compress -WarningAction SilentlyContinue } } -ExcludeProperty DeviceManagement

    #foreach ($Device in $Devices) {
    #    $Device.Inventory = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/InventoryDetails" | ConvertTo-Json
    #    ##$Device.Power = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/Power" | ConvertTo-Json
    #    #$Device.HardwareLogs = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/HardwareLogs"
    #    #$Device.RecentActivity = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/RecentActivity"
    #    ##$Device.SensorHealth = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/SensorHealth" | ConvertTo-Json
    #    #$Device.Settings = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/Settings"
    #    #$Device.SubSystemHealth = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/SubSystemHealth"
    #    ##if ($device.type -eq 1000){
    #    ##$Device.SystemUptime = (Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/SystemUpTime").systemUpTime
    #    ##}
    #    ##if ($device.type -eq 2000){$Device.SystemUptime = 0}
    #    ##$Device.Temperature = Get-OMEData "https://$omeserver/api/DeviceService/Devices($($Device.Id))/Temperature" | ConvertTo-Json
    #}

    #$test = $devices | Select-Object id, @{name = 'inventory'; expression = { Get-OMEData "https://$omeserver/api/DeviceService/Devices($($_.Id))/InventoryDetails" } }
    #$all = $test | Select-Object * -ExpandProperty inventory -ErrorAction SilentlyContinue
    #$deviceinventory = $all | Select-Object Id, InventoryType, @{name = 'Info'; expression = { $_.inventoryinfo | ConvertTo-Json -Compress } }
    #Invoke-PGSqlQuery -Type Insert -InputObject $deviceinventory -OnConflict 'Do Nothing' -Schema 'ome' -Table 'deviceinventory' -Truncate $true
    #$devices = $devices | Select-Object *, @{name = 'DeviceManagement'; expression = { $_.DeviceManagement | ConvertTo-Json -Compress } } -ExcludeProperty DeviceManagement
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'ome' -Table 'devices' -Truncate $true
        Invoke-PGSqlQuery -Type Insert -InputObject $deviceinventory -OnConflict 'Do Nothing' -Schema 'ome' -Table 'deviceinventory' -Truncate $true

        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

    
Function Get-OMEGroups {

    $Groups = Get-OMEData "https://$omeserver/api/GroupService/Groups"
    return $groups
}


Function Add-OMEGroup($groupname) {

    $groupmodel = [PSCustomObject]@{
        Name             = $groupname
        MembershipTypeId = 12
        ParentId         = 1021
    }

    $model = [PSCustomObject]@{
        GroupModel = $groupmodel
    }
    $json = $model | ConvertTo-Json

    $uri = "https://$omeserver/api/GroupService/Actions/GroupService.CreateGroup"

    Invoke-RestMethod -Uri $uri -Method Post -Body $json -Credential (Get-OMECreds) -ContentType 'application/json'

}

Function Add-OMESubnetGroups {

    
<#
$group = Get-OMEData "https://$omeserver/api/GroupService/Groups(10846)"
$QueryContextSummaries = Get-OMEData "https://$omeserver/api/QuerySupportService/QueryContextSummaries"
$devices = Get-OMEData "https://$omeserver/api/QuerySupportService/QueryContexts(2)"
$servers = Get-OMEData "https://$omeserver/api/QuerySupportService/QueryContexts(5)"
$groups = Get-OMEData "https://$omeserver/api/QuerySupportService/QueryContexts(3)"
$devices.fields | Select-Object name, id | Sort-Object name 
$groups.fields | Select-Object name, id | Sort-Object name | Where-Object { $_.id -eq 9 }
$servers.fields | Select-Object name, id | Sort-Object name | Where-Object { $_.id -eq 9 }
$devices.fields | Where-Object { $_.name -eq  "Device IP Address"}
#>


# API docs/operator info is at https://dl.dell.com/content/manual57961431-openmanage-enterprise-3-10-restful-api-guide.pdf?language=en-us

 

$idrac_subnets_query = @"
SELECT distinct name,site
FROM "ActiveDirectory".dns_a_records
join "ActiveDirectory".subnets on dns_a_records.data << subnets.name
where lower(hostname) like '%idrac'
order by site
"@

$idrac_subnets = Invoke-PGSqlQuery -Type Select -Query $idrac_subnets_query
[Regex]$Regex = '\d+\.\d+\.'
foreach ($subnettocreate in $idrac_subnets){
    [string]$subnet = $Regex.Match($subnettocreate.name).Groups[0].Value
    Add-OMEDynamicGroup -groupname $subnettocreate.site -subnet $subnet
}

}

Function Add-OMEDynamicGroup {
param(
    $groupname,
    $subnet
)

    $GroupModel = @{
        "Id" = 0
        "Name" = "$groupname"
        "GlobalStatus" = 0
        "DefinitionId" = 0
        "MembershipTypeId" = 24
        "ParentId" = 1022
    }
    $Conditions = @(
        @{
            "LogicalOperatorId" = 1
            "LeftParen" = $false
            "FieldId" = 81
            "OperatorId" = 11
            "Value" = "$subnet"
            "RightParen" = $false
        }
    )
    $GroupModelExtension = @{
        "FilterId" = 0
        "ContextId" = 2
        "Conditions" = $Conditions
    }
    $finalObject = @{
        "GroupModel" = $GroupModel
        "GroupModelExtension" = $GroupModelExtension
    }
    $json = $finalObject | ConvertTo-Json -Depth 5
    $uri = "https://$omeserver/api/GroupService/Actions/GroupService.CreateGroup"
    Invoke-RestMethod -Uri $uri -Method Post -Body $json -Credential (Get-OMECreds) -ContentType 'application/json'
}


Function Get-OMEFirmwareBaselines {

    $BaselineName = 'Name Here'
    $FirmwareBaselines = @()
    $FirmwareBaselines = Get-OMEData "https://$omeserver/api/UpdateService/Baselines" | Where-Object { $_.Name -eq $BaselineName }
    $FirmwareBaselines | Add-Member -MemberType NoteProperty -Name DeviceComplianceReports -Value @()
    
    foreach ($Baseline in $FirmwareBaselines) {
        $Baseline.DeviceComplianceReports = Get-OMEData ("https://$omeserver" + $Baseline.'DeviceComplianceReports@odata.navigationLink') 
    }

    $FirmwareBaselineValues = $FirmwareBaselines | Select-Object *, @{name = 'ComplianceSummary'; expression = { $_.ComplianceSummary | ConvertTo-Json -Compress -WarningAction SilentlyContinue } } -ExcludeProperty ComplianceSummary
    $FirmwareBaselineValues = $FirmwareBaselineValues | Select-Object *, @{name = 'DeviceComplianceReports'; expression = { $_.DeviceComplianceReports | ConvertTo-Json -Compress -WarningAction SilentlyContinue } } -ExcludeProperty DeviceComplianceReports
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $FirmwareBaselineValues -OnConflict 'Do Nothing' -Schema 'ome' -Table 'firmware_baselines' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    $pattern = '(?<=\/api\/UpdateService\/Baselines\()\d+(?=\)\/DeviceComplianceReports)'
    $devicecompliancereports = $FirmwareBaselines.DeviceComplianceReports | Select-Object *, @{name = 'baselineid'; expression = { ($_.'@odata.id' | Select-String -Pattern $pattern).matches.value } }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $devicecompliancereports -OnConflict 'Do Nothing' -Schema 'ome' -Table 'devicecompliancereports' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

    $properties = @(
        'Id',
        'Version',
        'CurrentVersion',
        'Path',
        'Name',
        'Criticality',
        'TargetIdentifier',
        'UpdateAction',
        'SourceName',
        'PrerequisiteInfo',
        'ImpactAssessment',
        'Uri',
        'RebootRequired',
        'ComplianceStatus',
        @{name = 'ComplianceDependencies'; expression = { $_.ComplianceDependencies | ConvertTo-Json -Compress -WarningAction SilentlyContinue } },
        'ComponentType',
        'DependencyUpgradeRequired',
        'DeviceId'
    )

    $componentcompliancereports = $devicecompliancereports | Select-Object deviceid -ExpandProperty componentcompliancereports -ErrorAction SilentlyContinue | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $componentcompliancereports -OnConflict 'Do Nothing' -Schema 'ome' -Table 'componentcompliancereports' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }



}

Function Invoke-OMEScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    switch ($Schedule) {
        '15Minute' {}
        'Hourly' { 
        }
        'Daily' {
            Write-Output 'Get-OMEDevices'; Get-OMEDevices
            Write-Output 'Get-OMEWarrantyInfo'; Get-OMEWarrantyInfo
            Write-Output 'Get-OMEFirmwareBaselines'; Get-OMEFirmwareBaselines
        }
    }

}









