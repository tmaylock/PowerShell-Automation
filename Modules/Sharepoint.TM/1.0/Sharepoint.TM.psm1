
Function Get-SharePointGroups {
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false
    $groups = Get-UnifiedGroup -ResultSize unlimited | Select-Object DisplayName, SharePointSiteUrl, ExternalDirectoryObjectID, WhenCreatedUTC, GUID
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $groups -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'sharepointgroups' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    Disconnect-ExchangeOnline -Confirm:$false
}
Function Get-SharePointGroupOwners {

    $query = @"
    SELECT externaldirectoryobjectid, displayname, sharepointsiteurl, guid
    FROM "Office365".sharepointgroups
"@

    $groups = Invoke-PGSqlQuery -Type Select -Query $query 

    $chunks = Get-Chunks -InputObject $groups -SplitSize 20
    $Headers = Get-MSGraphAPIHeaders
    [System.Collections.ArrayList]$owners = @()
    foreach ($chunk in $chunks) {
        $json = @()
        foreach ($group in $chunk) {
            $json += New-Object -TypeName PSObject -Property @{
                'id'     = $group.externaldirectoryobjectid.guid
                'method' = 'GET'
                'url'    = "/groups/$($group.externaldirectoryobjectid.guid)/owners"
            }
        }
        $jsonDoc = [pscustomobject]@{requests = $json } | ConvertTo-Json
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Headers $Headers -ContentType 'application/json' -Body $jsonDoc
        $data = $result.responses | Select-Object id, @{ Name = 'ownerid'; Expression = { $_.body.value.id } }

        foreach ($group in $data) {
            $groupid = $group.id
            $ownerids = $group.ownerid
            $ownerids.foreach(
                {
                    $obj = [PSCustomObject]@{ 
                        groupguid = $groupid
                        ownerguid = $_
                    }
                    [void]$owners.add($obj) 
                }
            )
        }
    }
    

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $owners -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'sharepointgroupowners' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-SharePointGroupMembers {
    $query = @"
    SELECT externaldirectoryobjectid, displayname, sharepointsiteurl, guid
    FROM "Office365".sharepointgroups
"@

    $groups = Invoke-PGSqlQuery -Type Select -Query $query

    $chunks = Get-Chunks -InputObject $groups -SplitSize 20
    $Headers = Get-MSGraphAPIHeaders

    [System.Collections.ArrayList]$members = @()
    foreach ($chunk in $chunks) {
        $json = @()
        foreach ($group in $chunk) {
            $json += New-Object -TypeName PSObject -Property @{
                'id'     = $group.externaldirectoryobjectid.guid
                'method' = 'GET'
                'url'    = "/groups/$($group.externaldirectoryobjectid.guid)/members"
            }
        }
        $jsonDoc = [pscustomobject]@{requests = $json } | ConvertTo-Json
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Headers $Headers -ContentType 'application/json' -Body $jsonDoc
        $data = $result.responses | Select-Object id, @{ Name = 'memberid'; Expression = { $_.body.value.id } }

        foreach ($group in $data) {
            $groupid = $group.id
            $memberids = $group.memberid
            $memberids.foreach(
                {
                    $obj = [PSCustomObject]@{ 
                        groupguid  = $groupid
                        memberguid = $_
                    }
                    [void]$members.add($obj)
                }
            )
        }
        
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $members -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'sharepointgroupmembers' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Invoke-SharepointScheduledFunction {
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
            Write-Output 'Get-SPSecurityListItems'; Get-SPSecurityListItems
        }
        'Daily' {
            Write-Output 'Get-SharePointGroups'; Get-SharePointGroups
            Write-Output 'Get-SharePointGroupOwners'; Get-SharePointGroupOwners
            Write-Output 'Get-SharePointGroupMembers'; Get-SharePointGroupMembers
        }
    }
 
}






