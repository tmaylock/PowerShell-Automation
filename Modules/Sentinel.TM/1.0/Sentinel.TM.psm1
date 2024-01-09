Function Get-AzureSentinelIncidents {
    $ResourceGroup = 'sentinel'
    $WorkspaceName = 'Sentinel'
    Connect-AzAccount -Credential (Get-O365Creds) | Out-Null
    $sentinelincidents = Get-AzSentinelIncident -Filter "properties/LastModifiedTimeUtc ge $("{0:s}" -f (Get-Date).AddMinutes(-60).ToUniversalTime())Z" -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName 

    $properties = @(
        'Id',
        'Name',
        'Type',
        'Etag',
        'Classification',
        'ClassificationComment',
        'ClassificationReason',
        'CreatedTimeUTC',
        'Description',
        'FirstActivityTimeUtc',
        'IncidentNumber',
        'IncidentUrl',
        'Labels',
        'LastActivityTimeUtc',
        'LastModifiedTimeUtc',
        'Severity',
        'Status',
        'Title',
        @{name = 'AdditonalData'; expression = { $_.AdditonalData | ConvertTo-Json -Compress } },
        @{name = 'Owner'; expression = { $_.Owner | ConvertTo-Json -Compress } }
    )
    if ($sentinelincidents) {
        $inputobject = $sentinelincidents | Select-Object -Property $properties
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'sentinel' -Table 'incidents' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) - No Incidents" -Severity 1 -Schedule $Schedule
    }
}




Function Invoke-SentinelScheduledFunction {
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
            Write-Output "Get-AzureSentinelIncidents"; Get-AzureSentinelIncidents
        }
        'Daily' {            
        }
    }

}




