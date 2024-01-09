
Function Get-AzureApplications {

    Connect-MSGraph
    $AzureAdApplications = Get-MgApplication -All

    $properties = @(
        @{Name = 'addins'; Expression = { $_.addins | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'api'; Expression = { $_.api | ConvertTo-Json -WarningAction SilentlyContinue } },
        'appid',
        'applicationtemplateid',
        @{Name = 'approles'; Expression = { $_.approles | ConvertTo-Json -WarningAction SilentlyContinue } },
        'certification',
        'createddatetime',
        'defaultredirecturi',
        'deleteddatetime',
        'description',
        'disabledbymicrosoftstatus',
        'displayname',
        'groupmembershipclaims',
        'id',
        @{Name = 'identifieruris'; Expression = { $_.identifieruris | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'info'; Expression = { $_.info | ConvertTo-Json -WarningAction SilentlyContinue } },
        'isdeviceonlyauthsupported',
        'isfallbackpublicclient',
        @{Name = 'keycredentials'; Expression = { $_.keycredentials | ConvertTo-Json -WarningAction SilentlyContinue } },
        'notes',
        @{Name = 'optionalclaims'; Expression = { $_.optionalclaims | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'parentalcontrolsettings'; Expression = { $_.parentalcontrolsettings | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'passwordcredentials'; Expression = { $_.passwordcredentials | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'publicclient'; Expression = { $_.publicclient | ConvertTo-Json -WarningAction SilentlyContinue } },
        'publisherdomain',
        @{Name = 'requiredresourceaccess'; Expression = { $_.requiredresourceaccess | ConvertTo-Json -WarningAction SilentlyContinue } },
        'servicemanagementreference',
        'signinaudience',
        @{Name = 'spa'; Expression = { $_.spa | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'tags'; Expression = { $_.tags | ConvertTo-Json -WarningAction SilentlyContinue } },
        'tokenencryptionkeyid',
        @{Name = 'verifiedpublisher'; Expression = { $_.verifiedpublisher | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'web'; Expression = { $_.web | ConvertTo-Json -WarningAction SilentlyContinue } })


    Invoke-PGSqlQuery -Type Insert -InputObject ($AzureAdApplications | Select-Object -Property $properties) -Schema azuread -Table applications -OnConflict 'Do Nothing' -Truncate $true

}
Function Invoke-AzureScheduledFunction {
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
            Write-Output 'Get-AzureApplications'; Get-AzureApplications
        }
    }
 
}
