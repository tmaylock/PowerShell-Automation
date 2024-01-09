



Function Get-O365Mailboxes {
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false
    $properties = @(
        'externaldirectoryobjectid',    
        'userprincipalname',
        'alias',
        'displayname',
        'primarysmtpaddress',
        'recipienttype',
        'recipienttypedetails',
        'identity',
        'id',
        'name',
        'distinguishedname',
        'guid')

    $mailboxes = Get-EXOMailbox -Filter "ExternalDirectoryObjectId -ne `$null" -Properties $properties -ResultSize:Unlimited
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $mailboxes -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'mailboxes' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule

    }

    
}


Function Get-O365SharedMailboxPermissions {
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false

    $sharedmailboxes = $mailboxes.Where({ $_.recipienttypedetails -eq 'SharedMailbox' })
    $permissions = ($sharedmailboxes | Get-EXOMailboxPermission | Select-Object Identity, User, AccessRights).Where({ ($_.user -like '*@*') })

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $permissions -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'mailboxpermissions' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-O365Mailboxstatistics {
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false
    $properties = @('DisplayName',             
        'LastLogonTime',           
        'MailboxGuid',             
        'DeletedItemCount',        
        'ItemCount',               
        @{name = 'totaldeleteditemsize'; expression = { ($_.TotalDeletedItemSize.value).ToBytes() } },
        @{name = 'totalitemsize'; expression = { ($_.TotalItemSize.value).ToBytes() } }    )      
      
    $statistics = $mailboxes | Get-EXOMailboxStatistics -Properties LastLogonTime | Select-Object $properties 

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $statistics -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'mailboxstatistics' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}






Function Get-Office365UserID {
    Connect-MSGraph
    
    $properties = @(
        'AccountEnabled',
        'AssignedLicenses',
        'DisplayName',
        'City',
        'CompanyName',
        'Country',
        'CreatedDateTime',
        'Department',
        'EmployeeId'
        'GivenName',
        'Id',
        'JobTitle',
        'LastPasswordChangeDateTime',
        'LicenseAssignmentStates',
        'Mail',
        'ManagedDevices',
        'MobilePhone',
        'OfficeLocation',
        'PostalCode',
        'State',
        'StreetAddress',
        'Surname',
        'UsageLocation',
        'UserPrincipalName',
        'UserType',
        'manager',
        'proxyaddresses',
        'SignInActivity'
    )

    $selproperties = @(
        'AccountEnabled',
        'AssignedLicenses',
        'DisplayName',
        'City',
        'CompanyName',
        'Country',
        'CreatedDateTime',
        'Department',
        'EmployeeId'
        'GivenName',
        'Id',
        'JobTitle',
        'LastPasswordChangeDateTime',
        'LicenseAssignmentStates',
        'Mail',
        'ManagedDevices',
        'MobilePhone',
        'OfficeLocation',
        'PostalCode',
        'State',
        'StreetAddress',
        'Surname',
        'UsageLocation',
        'UserPrincipalName',
        'UserType',
        @{Name = 'managerid'; Expression = { $_.manager.id } },
        @{Name = 'proxyaddresses'; Expression = { $_.proxyAddresses.foreach({ [PSCustomObject]@{
                            Name  = ($_ -split ':')[0]
                            Value = ($_ -split ':')[1]
                        } }) | ConvertTo-Json }},
        @{Name = 'SignInActivity'; Expression = { $_.SignInActivity | ConvertTo-Json -WarningAction SilentlyContinue } }          
    )

     
    $users = Get-MgUser -All -Property $properties -ExpandProperty Manager
    $inputobject = $users | Select-Object -Property $selproperties -ExcludeProperty LicenseAssignmentStates

    Get-Office365UserLicenses -Users $users

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'userid' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}

Function Get-Office365UserSigninHistory {
  
$signin_query = @"
with latest_signin as (
	select userprincipalname, greatest((signinactivity->>'LastNonInteractiveSignInDateTime')::date,(signinactivity->>'LastSignInDateTime')::date) as date
	FROM "Office365".USERID
		)
	insert into "Office365".user_signin_history
	select * from latest_signin
	where date is not null
	on conflict do nothing
"@



    try {
        Invoke-PGSqlQuery -Type Select -Query $signin_query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Set-Office365LicensedUsers {

    # Only upn's where skuid is ENTERPRISEPACK or SPE_F1
    $query = "SELECT samaccountname FROM `"Office365`".userlicensedetail " `
        + "WHERE skuid IN ('6fd2c87f-b296-42f0-b197-1e91e994b900','66b55226-6b4f-492c-910c-a3b7a3c9d993');"

    $results = Invoke-PGSqlQuery -Type Select -Query $query
    if ($results) {
        
        $currentmembers = Get-ADGroupMember -Identity 'Office365LicensedUsers' -Server $

        #Remove extra members
        $extra = Compare-Object $currentmembers $results -Property samaccountname -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
        if ($extra) {
            Remove-ADGroupMember -Identity 'Office365LicensedUsers' -Members $extra.samaccountname -Confirm:$false
        }
            
        #Add missing members
        $missing = Compare-Object $currentmembers $results -Property samaccountname -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($missing) {
            Add-ADGroupMember -Identity 'Office365LicensedUsers' -Members $missing.samaccountname -Confirm:$false
        }
        
    }
}
Function Get-Office365LicenseTotals {

    $query = @'
    insert into "Office365".licensetotals (
        select site,
    sum (case when skupartnumber = 'SPE_F1' then 1 else 0 end) as "F1",
    sum (case when skupartnumber = 'ENTERPRISEPACK' then 1 else 0 end) as "E3",
    sum (case when skupartnumber = 'EMS' then 1 else 0 end) as "EMS",
         now()::date
    from "ActiveDirectory".users
    inner join "Office365".userid on users.userprincipalname  = userid.userprincipalname
    inner join "Office365".licensing on userid.id = licensing.userid
    inner join "Office365".licensingsku on licensing.licenseskuid = licensingsku.skuid
    GROUP BY site	
    ) on conflict (site,date) DO UPDATE SET f1=EXCLUDED.f1,e3=EXCLUDED.e3,ems=EXCLUDED.ems;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query 
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Get-Office365UserLicenses {
    param (
        [Parameter(Mandatory = $true)]
        $Users
    )
    [System.Collections.ArrayList]$licensing = @()
    foreach ($user in $users) {
        ($user.AssignedLicenses.skuid).ForEach( { [void]$licensing.add([PSCustomObject]@{ userid = $user.id; LicenseSKUId = $_ }) } );
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $licensing -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'licensing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}



Function Get-Office365LicenseSKU {

    Connect-MSGraph

    $properties = @(
        @{Name = 'skuid'; Expression = { $_.id.replace("$tenant_id`_", '') } },
        'skupartnumber'
    )
    $skus = Get-MgSubscribedSku | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $skus -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'licensingsku' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-Office365AuditLog {    
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false
    $startdate = (Get-Date).AddDays(-2).ToString('MM/d/yyyy')
    $enddate = (Get-Date).AddDays(-1).ToString('MM/d/yyyy')
    $logs = Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -Operations SharingSet, SharingInvitationCreated, AnonymousLinkCreated, SecureLinkCreated, AddedToSecureLink -ResultSize 5000
    if ($logs) {
        $inputobject = $logs | Select-Object creationdate, userids, operations, auditdata, identity, resultindex
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'auditlog' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
}



Function Get-MailboxRecoverableItems {
    Connect-ExchangeOnline -Credential (Get-O365Creds) -ShowBanner:$false
    $Properties = @(
        "name",
        @{name = 'identity'; expression = { ($_.identity).split('\')[0] } },
        @{name = 'size'; expression = { ($_.foldersize).split('(')[-1].Replace(' bytes)', '').Replace(',', '') } },
        @{Name='items';Expression={$_.ItemsInFolderAndSubfolders}},
        @{name = 'date'; expression = { ([datetime]::now).ToString('yyyy-MM-dd') } }
    )

    $mailboxstats = $mailboxes | Get-EXOMailboxFolderStatistics -Folderscope RecoverableItems -ErrorAction SilentlyContinue | Select-Object -property  $Properties
    
    [regex]$guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'
    $inputobject  = $mailboxstats | Where-Object { $_.identity -match $guidRegex -and $_.size -ne 0 }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'Office365' -Table 'recoverableitems' -Truncate $false
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}
Function Get-Teams {
    Connect-MSGraph
    $properties = @(
        @{Name = 'groupid'; Expression = { $_.id } },
        'displayname',
        'description',
        'visibility',
        'createddatetime'
    )
    $Teams = Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')" -All -Property @('id', 'displayname', 'description', 'visibility', 'CreatedDateTime')
    $inputobject = $Teams | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'teams' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}
Function Get-TeamMembers {
    $query = "SELECT groupid FROM `"Office365`".teams;"
    $teams = Invoke-PGSqlQuery -Type Select -Query $query

    $chunks = Get-Chunks -InputObject $teams -SplitSize 20
    $Headers = Get-MSGraphAPIHeaders
 
    [System.Collections.ArrayList]$members = @()
    foreach ($chunk in $chunks) {
       
   
        $json = @()
        foreach ($team in $chunk) {
            $json += New-Object -TypeName PSObject -Property @{
                'id'     = $team.groupid
                'method' = 'GET'
                'url'    = "/teams/$($team.groupid)/members"
            }
        }
        $jsonDoc = [pscustomobject]@{requests = $json } | ConvertTo-Json
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Headers $Headers -ContentType 'application/json' -Body $jsonDoc
        $data = $result.responses | Select-Object id, @{ Name = 'value'; Expression = { $_.body.value } }

        foreach ($team in $data) {
            $team.value.foreach(
                {
                    $obj = [PSCustomObject]@{ 
                        groupid = $team.id
                        userid  = $_.userid
                        role    = ($_.roles[0]) ? $($_.roles[0]) : $('member')
                    }
                    [void]$members.add($obj)
                }
            )
        }
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $members -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'teammembers' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-Office365UserLoggedIn {  
 
    Connect-MSGraph
  
    $start = (Get-Date).AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $end = (Get-Date).AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $logs = Get-MgAuditLogSignIn -Filter "CreatedDateTime ge $start and CreatedDateTime le $end and ConditionalAccessStatus eq 'success'" | Select-Object -Property @('UserPrincipalName', 'CreatedDateTime')


    if ($logs) {
        $groups = $logs | Group-Object -Property UserPrincipalName
        $all = @()
        foreach ($group in $groups) {
            if ($group.count -gt 1) {
                $log = ($group.group | Sort-Object -Property creationdate -Descending)[0]
            }
            if ($group.count -eq 1) {
                $log = $group.group
            }
            $all += $log
        }
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $all -OnConflict 'Set Excluded' -Schema 'Office365' -Table 'userloggedin' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
}

Function Get-O365PacFile {

    # Copyright (c) Microsoft Corporation. All rights reserved.
    # Licensed under the MIT License.
    
    <#PSScriptInfo
    
    .VERSION 1.0.4
    
    .AUTHOR Microsoft Corporation
    
    .GUID 7f692977-e76c-4582-97d5-9989850a2529
    
    .COMPANYNAME Microsoft
    
    .COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved.
    Licensed under the MIT License.
    
    .TAGS PAC Microsoft Microsoft365 365
    
    .LICENSEURI
    
    .PROJECTURI http://aka.ms/ipurlws
    
    .ICONURI
    
    .EXTERNALMODULEDEPENDENCIES
    
    .REQUIREDSCRIPTS
    
    .EXTERNALSCRIPTDEPENDENCIES
    
    .RELEASENOTES
    
    #>
    
    <#
    
    .SYNOPSIS
    
    Create a PAC file for Microsoft 365 prioritized connectivity
    
    .DESCRIPTION
    
    This script will access updated information to create a PAC file to prioritize Microsoft 365 Urls for
    better access to the service. This script will allow you to create different types of files depending
    on how traffic needs to be prioritized.
    
    .PARAMETER Instance
    
    The service instance inside Microsoft 365.
    
    .PARAMETER ClientRequestId
    
    The client request id to connect to the web service to query up to date Urls.
    
    .PARAMETER DirectProxySettings
    
    The direct proxy settings for priority traffic.
    
    .PARAMETER DefaultProxySettings
    
    The default proxy settings for non priority traffic.
    
    .PARAMETER Type
    
    The type of prioritization to give. Valid values are 1 and 2, which are 2 different modes of operation.
    Type 1 will send Optimize traffic to the direct route. Type 2 will send Optimize and Allow traffic to
    the direct route.
    
    .PARAMETER Lowercase
    
    Flag this to include lowercase transformation into the PAC file for the host name matching.
    
    .PARAMETER TenantName
    
    The tenant name to replace wildcard Urls in the webservice.
    
    .PARAMETER ServiceAreas
    
    The service areas to filter endpoints by in the webservice.
    
    .PARAMETER FilePath
    
    The file to print the content to.
    
    .EXAMPLE
    
    Get-PacFile.ps1 -ClientRequestId b10c5ed1-bad1-445f-b386-b919946339a7 -DefaultProxySettings "PROXY 4.4.4.4:70" -FilePath type1.pac
    
    .EXAMPLE
    
    Get-PacFile.ps1 -ClientRequestId b10c5ed1-bad1-445f-b386-b919946339a7 -Instance China -Type 2 -DefaultProxySettings "PROXY 4.4.4.4:70" -FilePath type2.pac
    
    .EXAMPLE
    
    Get-PacFile.ps1 -ClientRequestId b10c5ed1-bad1-445f-b386-b919946339a7 -Instance WorldWide -Lowercase -TenantName tenantName -ServiceAreas Sharepoint,Skype
    
    #>
    
    #Requires -Version 2
    
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Worldwide', 'Germany', 'China', 'USGovDoD', 'USGovGCCHigh')]
        [String] $Instance = 'Worldwide',
    
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $ClientRequestId,
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $DirectProxySettings = 'DIRECT',
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $DefaultProxySettings = 'PROXY 10.10.10.10:8080',
    
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2)]
        [int] $Type = 1,
    
        [Parameter(Mandatory = $false)]
        [switch] $Lowercase = $false,
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantName,
    
        [Parameter(Mandatory = $false)]
        [ValidateSet('Exchange', 'Skype', 'SharePoint', 'Common')]
        [string[]] $ServiceAreas,
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath
    )
    
    ##################################################################################################################
    ### Global constants
    ##################################################################################################################
    
    $baseServiceUrl = "https://endpoints.office.com/endpoints/$Instance/?ClientRequestId={$ClientRequestId}"
    $directProxyVarName = 'direct'
    $defaultProxyVarName = 'proxyServer'
    $bl = "`r`n"
    
    ##################################################################################################################
    ### Functions to create PAC files
    ##################################################################################################################
    
    function Get-PacClauses {
        param(
            [Parameter(Mandatory = $false)]
            [string[]] $Urls,
    
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [String] $ReturnVarName
        )
    
        if (!$Urls) {
            return ''
        }
    
        $clauses = (($Urls | ForEach-Object { "shExpMatch(host, `"$_`")" }) -Join "$bl        || ")
    
        @"
        if($clauses)
        {
            return $ReturnVarName;
        }
"@
    }
    
    function Get-PacString {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array[]] $MapVarUrls
        )
    
        @"
    // This PAC file will provide proxy config to Microsoft 365 services
    //  using data from the public web service for all endpoints
    function FindProxyForURL(url, host)
    {
        var $directProxyVarName = "$DirectProxySettings";
        var $defaultProxyVarName = "$DefaultProxySettings";
    
    $( if ($Lowercase) { '    host = host.toLowerCase();' })
    
    $( ($MapVarUrls | ForEach-Object { Get-PACClauses -ReturnVarName $_.Item1 -Urls $_.Item2 }) -Join "$bl$bl" )
    
        return $defaultProxyVarName;
    }
"@ -replace "($bl){3,}", "$bl$bl" # Collapse more than one blank line in the PAC file so it looks better.
    }
    
    ##################################################################################################################
    ### Functions to get and filter endpoints
    ##################################################################################################################
    
    function Get-Regex {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $Fqdn
        )
    
        return '^' + $Fqdn.Replace('.', '\.').Replace('*', '.*').Replace('?', '.') + '$'
    }
    
    function Get-RegexMatches {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $ToMatch,
    
            [Parameter(Mandatory = $false)]
            [string[]] $MatchList
        )
    
        if (!$MatchList) {
            return $false
        }
        foreach ($regex in $MatchList) {
            if ($regex -ne $ToMatch -and $ToMatch -match (Get-Regex $regex)) {
                return $true
            }
        }
        return $false
    }
    
    function Get-Endpoints {
        $url = $baseServiceUrl
        if ($TenantName) {
            $url += "&TenantName=$TenantName"
        }
        if ($ServiceAreas) {
            $url += '&ServiceAreas=' + ($ServiceAreas -Join ',')
        }
        return Invoke-RestMethod -Uri $url
    }
    
    function Get-Urls {
        param(
            [Parameter(Mandatory = $false)]
            [psobject[]] $Endpoints
        )
    
        if ($Endpoints) {
            return $Endpoints | Where-Object { $_.urls } | ForEach-Object { $_.urls } | Sort-Object -Unique
        }
        return @()
    }
    
    function Get-UrlVarTuple {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $VarName,
    
            [Parameter(Mandatory = $false)]
            [string[]] $Urls
        )
        return New-Object 'Tuple[string,string[]]'($VarName, $Urls)
    }
    
    function Get-MapVarUrls {
        Write-Verbose "Retrieving all endpoints for instance $Instance from web service."
        $Endpoints = Get-Endpoints
    
        if ($Type -eq 1) {
            $directUrls = Get-Urls ($Endpoints | Where-Object { $_.category -eq 'Optimize' })
            $nonDirectPriorityUrls = Get-Urls ($Endpoints | Where-Object { $_.category -ne 'Optimize' }) | Where-Object { Get-RegexMatches $_ $directUrls }
            return @(
                Get-UrlVarTuple -VarName $defaultProxyVarName -Urls $nonDirectPriorityUrls
                Get-UrlVarTuple -VarName $directProxyVarName -Urls $directUrls
            )
        }
        elseif ($Type -eq 2) {
            $directUrls = Get-Urls ($Endpoints | Where-Object { $_.category -in @('Optimize', 'Allow') })
            $nonDirectPriorityUrls = Get-Urls ($Endpoints | Where-Object { $_.category -notin @('Optimize', 'Allow') }) | Where-Object { Get-RegexMatches $_ $directUrls }
            $nonDirectPriorityUrls = Get-Urls ($Endpoints | Where-Object { ($_.category -notin @('Optimize', 'Allow')) -and ($_.notes -notlike '*Android*') -and ($_.notes -notlike '*iOS*') }) | Where-Object { ($_ -notin ('www.youtube.com')) -and ($_ -notlike '*facebook*') }
    
            return @(
                Get-UrlVarTuple -VarName $defaultProxyVarName -Urls $nonDirectPriorityUrls
                Get-UrlVarTuple -VarName $directProxyVarName -Urls $directUrls
            )
        }
    }
    
    ##################################################################################################################
    ### Main script
    ##################################################################################################################
    
    $content = Get-PacString (Get-MapVarUrls)
    
    if ($FilePath) {
        $content | Out-File -FilePath $FilePath -Encoding ascii
    }
    else {
        $content
    }
    
}

Function Set-O365PacFile {
    $ClientRequestId = [guid]::NewGuid()
    $pac = Get-O365PacFile -ClientRequestId $ClientRequestId -Instance Worldwide -Type 2 -TenantName $mycompany -DefaultProxySettings 'PROXY localhost:10000'

    $trustedsites = @"
        || shExpMatch(host, '*.mycompany.com')
        || isInNet(host, "10.0.0.0", "255.0.0.0")
        || isInNet(host, "192.168.0.0", "255.255.0.0"))
"@

    $pac = [System.Text.RegularExpressions.Regex]::Replace($pac, '^(\s+\|\| shExpMatch\(host, .*\))(\))(?=\r\n\s+{\r\n\s+return direct;\r\n\s+})', "`${1}`r`n$trustedsites", [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $pac = [System.Text.RegularExpressions.Regex]::Replace($pac, '(\)\s+{\r\n\s+return proxyServer;\r\n\s+}\r\n\s+if\()', "`r`n        || ", [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $pac > E:\PowerShell\temp\internet_disabled.pac

}

Function Invoke-O365PSTAuditCleanup {
    $query = @'
	delete FROM inventory.pstaudit
	where lower(username) not in (select lower(samaccountname) from "ActiveDirectory".users);
	delete from inventory.odkfm
	where hostname not in (select name from "ActiveDirectory".computers);
'@
    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Invoke-O365ScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    
    switch ($Schedule) {
        '15Minute' {}
        'Hourly' { 
            if ((Get-Date).Hour % 6 -eq 0){
                Write-Output 'Get-Office365UserID'; Get-Office365UserID
                Write-Output 'Get-Office365UserSigninHistory'; Get-Office365UserSigninHistory
                }
            Write-Output 'Get-Office365UserLoggedIn'; Get-Office365UserLoggedIn
            

        }
        'Daily' {
            
    
            Write-Output 'Get-Office365LicenseSKU'; Get-Office365LicenseSKU
            Write-Output 'Get-Office365LicenseTotals'; Get-Office365LicenseTotals
            Write-Output 'Set-PmGblOffice365LicensedUsers'; Set-PmGblOffice365LicensedUsers
            Write-Output 'Get-Office365AuditLog'; Get-Office365AuditLog
            Write-Output 'Get-O365Mailboxes'; Get-O365Mailboxes
            Write-Output 'Get-O365SharedMailboxPermissions'; Get-O365SharedMailboxPermissions
            Write-Output 'Get-O365SharedMailboxstatistics'; Get-O365Mailboxstatistics
            Write-Output 'Get-MailboxRecoverableItems'; Get-MailboxRecoverableItems
            Write-Output 'Invoke-O365PSTAuditCleanup'; Invoke-O365PSTAuditCleanup
            Write-Output 'Get-Teams'; Get-Teams
            Write-Output 'Get-TeamMembers'; Get-TeamMembers
            Disconnect-ExchangeOnline -Confirm:$false
        }
    }

}

