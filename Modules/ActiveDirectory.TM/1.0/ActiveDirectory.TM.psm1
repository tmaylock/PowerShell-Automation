<#
/* Group Membership Function for Postgresql */

CREATE OR REPLACE FUNCTION "ActiveDirectory".group_members(
	groupn text)
    RETURNS TABLE(group_name text, group_guid uuid, group_dn text, member_dn text, member_name text, member_class text, member_guid uuid) 
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE PARALLEL UNSAFE
    ROWS 1000

AS $BODY$
declare groupn text;
begin
return query
WITH RECURSIVE members AS (
	SELECT
		groupmembers.groupname, groupmembers.groupguid, 
		groupmembers.groupdn, groupmembers.memberdn, 
		groupmembers.membername, groupmembers.memberclass, groupmembers.memberguid
	FROM
		"ActiveDirectory".groupmembers 
	WHERE
		groupmembers.groupname = $1
	UNION
		SELECT
		gm.groupname, gm.groupguid, gm.groupdn, gm.memberdn, gm.membername, gm.memberclass, gm.memberguid
		FROM
			"ActiveDirectory".groupmembers gm
		INNER JOIN members m ON m.membername = gm.groupname
) SELECT
	*
FROM
	members;
end;
$BODY$;

ALTER FUNCTION "ActiveDirectory".group_members(text)
    OWNER TO postgres;



#>
Function Get-ADGroupsAndMembers {
 
        
        $groups = Get-ADGroup -Filter * -Properties member -Server $domain_controller | Select-Object Name, ObjectGUID, member, DistinguishedName
        $grouplist = $groups | Select-Object name, @{name = 'guid'; expression = { $_.ObjectGUID } }, DistinguishedName

        [System.Collections.ArrayList]$memberships = @()
        foreach ($group in $groups) {
            $groupguid = $group.ObjectGUID
            foreach ($member in $group.member) {
                [void]$memberships.add([PSCustomObject]@{ groupGUID = $groupguid; Memberdn = $member })
            }
        }
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $grouplist -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'groups' -Truncate $true
            Invoke-PGSqlQuery -Type Insert -InputObject $memberships -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'groupmembership' -Truncate $true
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
        finally {
            $groups = $null
            $grouplist = $null
            $memberships = $null
        }
    
}


Function Get-ADComputerVersionTotals {


    $computer_version_totals = @'
	insert into "ActiveDirectory".clientversiontotals (
    select now()::date,site, osmajorversion, osminorversion,count(*) as total
    from "ActiveDirectory".computers
    where enabled = 'True' and ostype = 'Client'
    group by osmajorversion,osminorversion,site
	)
    on conflict (date,site,osmajorversion,osminorversion) DO UPDATE SET total=EXCLUDED.total;
'@
    try {
        Invoke-PGSqlQuery -Type Select -Query $computer_version_totals
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-ADServerVersionTotals {


    $server_version_totals = @'
    insert into "ActiveDirectory".serverversiontotals (
	    select now()::date, site, osmajorversion,osminorversion, count(*) as total, operatingsystem
    from "ActiveDirectory".computers
    where enabled = 'True' and ostype = 'Server'
    group by osmajorversion,osminorversion,site,operatingsystem
	) on conflict (date,site,osmajorversion,osminorversion,operatingsystem) DO UPDATE SET total=EXCLUDED.total;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $server_version_totals
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-ADComputers {


    $properties = @(
        @{name = 'name'; expression = { $_.name.ToUpper() } },
        @{name = 'site'; expression = { ($_.DistinguishedName).split(',')[-4].replace('OU=', '').Replace('CN=', '') } },
        'DistinguishedName',
        'OperatingSystem',
        @{name = 'osmajorversion'; expression = { [double]($_.operatingsystemversion).split(' ')[0] } },
        @{name = 'osminorversion'; expression = { [int]($_.operatingsystemversion).split(' ')[1].replace('(', '').replace(')', '') } },
        @{name = 'ostype'; expression = { if ($_.OperatingSystem -like '*server*') { 'Server' } else { 'Client' } } },
        'enabled',
        'Description',
        'lastlogondate',
        'objectguid'

    )

    $filter = "(operatingsystem -like '*Windows*' -or operatingsystem -like '*Hyper-V*') -and serviceprincipalname -notlike '*msclustervirtualserver*'"
    $adproperties = @(
        'operatingsystem',
        'operatingsystemversion',
        'description',
        'lastlogondate',
        'servicePrincipalName'
    )

    $inputobject = Get-ADComputer -Filter $filter -Properties $adproperties -Server $domain_controller | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'computers' -Truncate $True
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
 
}

Function Get-ADObjects {
    
    $properties = @(
        'distinguishedname', 
        'name', 
        @{name = 'class'; expression = { $_.objectclass } }, 
        @{name = 'guid'; expression = { $_.objectguid } }, 
        'whenchanged', 
        'whencreated',
        'objectSid')

    $Objects = Get-ADObject -Filter * -Properties distinguishedname, name, objectclass, objectguid, whenchanged, whencreated, objectSid -Server $domain_controller | Select-Object $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $Objects -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'objects' -Truncate $True
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-ADUsers {
  

    $properties = @(
        'objectguid', 
        'cn',
        'name', 
        'distinguishedname', 
        'userprincipalname', 
        'samaccountname', 
        'mail', 
        'enabled', 
        'targetaddress', 
        'co', 
        'passwordneverexpires',
        'displayname',
        'lastLogon',
        'lastLogonTimestamp',
        'PasswordNotRequired',
        'description',
        'GivenName',
        'Surname',
        'Title',
        'scriptpath',
        'homedirectory',
        'employeeid',
        'department',
        'manager',
        'proxyaddresses',
        'extensionAttribute5'
    )

    $selproperties = @(
        'name', 
        'displayname', 
        'description', 
        @{name = 'guid'; expression = { $_.ObjectGUID } }, 
        'DistinguishedName'
        'UserPrincipalName', 
        'samaccountname', 
        'mail',
        @{name = 'site'; expression = { ($_.DistinguishedName).split(',')[-4].replace('OU=', '').Replace('CN=', '') } },
        'enabled',
        'targetaddress',
        @{name = 'country'; expression = { $_.co } },
        'passwordneverexpires',
        'passwordnotrequired',
        @{name = 'ou'; expression = { $_.distinguishedname.replace("CN=$($_.cn),", '') } },
        @{name = 'lastlogon'; expression = { [datetime]::FromFileTime($_.lastLogon) } },
        @{name = 'lastlogontimestamp'; expression = { [datetime]::FromFileTime($_.lastLogonTimestamp) } },
        'givenname',
        'surname',
        'title',
        @{name = 'logonscript'; expression = { $_.scriptpath } },
        'homedirectory',
        'employeeid',
        'department',
        'manager',
        @{Name = 'proxyaddresses'; Expression = { $_.proxyAddresses.foreach({ [PSCustomObject]@{
                            Name  = ($_ -split ':')[0]
                            Value = ($_ -split ':')[1]
                        } }) | ConvertTo-Json }
        },
        @{Name = 'worklocation'; Expression = { $_.extensionAttribute5 } }
    )

    $inputobject = Get-ADUser -Filter * -Properties $properties -Server $domain_controller | Select-Object -Property $selproperties -ExcludeProperty ProxyAddresses

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'users' -Truncate $True
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-ADUserWorkstations {
    
    $users = Get-ADUser -Filter 'userWorkstations -like "*"' -Properties userprincipalname, userWorkstations -Server $domain_controller | Select-Object userprincipalname, userWorkstations
        
    [System.Collections.ArrayList]$userWorkstations = @()
    foreach ($user in $users) {
        $userprincipalname = $user.userprincipalname
        foreach ($workstation in $user.userWorkstations.Split(',')) {
            $obj = [PSCustomObject]@{ userprincipalname = $userprincipalname; userWorkstation = $workstation }; [void]$userWorkstations.add($obj)
        }
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $userWorkstations -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'userworkstations' -Truncate $True
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Get-ADUserWorkstationsTotals {

    $ADUserWorkstationsTotals = @'
	insert into metrics.running_totals (
		select now()::date, site, metric, count(*) as value from (
        SELECT distinct(userprincipalname)
        ,site
        ,case 
        when (passwordneverexpires = 'True' and userworkstation is not null) then 'PasswordNeverExpires_Configured'
        when (passwordneverexpires = 'True' and userworkstation is null) then 'PasswordNeverExpires_Missing'
        when passwordneverexpires = 'False' then 'PasswordNeverExpires_Compliant' else null
        end as metric
        FROM "ActiveDirectory".users
        left join "ActiveDirectory".userworkstations USING (userprincipalname)
        where enabled = 'True'
        ) x group by site, metric
		) on conflict (time,site,metric) DO UPDATE SET value=EXCLUDED.value;
'@
        
    try {
        Invoke-PGSqlQuery -Type Select -Query $ADUserWorkstationsTotals
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Invoke-ADUserCleanup {

    
    $cleanup_query = @"
SELECT guid, userprincipalname,  enabled, daysremaining
        FROM `"ActiveDirectory`".users
        left join `"ActiveDirectory`".adcleanup using (guid)
        where site != 'CN=Users' 
        and enabled = 'True'
        and daysremaining <= 0
"@

    $cleanup_users = Invoke-PGSqlQuery -Type Select -Query $cleanup_query
   
    foreach ($user in $cleanup_users) {
        #Disable-ADAccount -Identity $user.guid -Confirm:$false -ErrorAction Stop
        $inputobject = $user | Select-Object @{name = 'timestamp'; expression = { ([datetime]::now).ToString('yyyy-MM-ddTHH:mm:ss') } }, guid, userprincipalname
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'ActiveDirectory' -Table 'cleanuplog' -Truncate $false
    }
    
}
   
Function Get-ADSubnets {
    
    $objRootDSE = [System.DirectoryServices.DirectoryEntry] 'LDAP://rootDSE'
    
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry('LDAP://cn=subnets,cn=sites,' + $objRootDSE.ConfigurationNamingContext)
    $Searcher.PageSize = 10000
    $Searcher.SearchScope = 'Subtree'
    $Searcher.Filter = '(objectClass=subnet)'
    
    $Properties = @('cn', 'location', 'siteobject')
    $Searcher.PropertiesToLoad.AddRange(@($Properties))
    $Subnets = $Searcher.FindAll()
    
    [Regex] $RegexCN = 'CN=(.*?),.*'
    $properties = @(
        @{Name = 'Name'; Expression = { [string] $_.Properties['cn'] } },
        @{Name = 'Location'; Expression = { [string] $_.Properties['location'] } },
        @{Name = 'Site'; Expression = { [string] $RegexCN.Match( $_.Properties['siteobject']).Groups[1].Value } },
        @{Name = 'InputAddress'; Expression = { (([string]$_.Properties['cn']).Split('/'))[0] } },
        @{Name = 'Prefix'; Expression = { (([string]$_.Properties['cn']).Split('/'))[1] } },
        @{Name = 'ObjInputAddress'; Expression = { [System.Net.IPAddress](([string]$_.Properties['cn']).Split('/'))[0] } }
    )

    $adsubnets = $subnets | Select-Object -Property $Properties `
    | Select-Object *, @{Name = 'Object'; Expression = { Get-IPv4 -Obj ($_ | Select-Object name, location, site) -ObjInputAddress $_.ObjInputAddress -Prefix $_.prefix } } `
    | Select-Object -ExpandProperty Object

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $adsubnets -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'subnets' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Get-ADDHCPScopes {
   
    $skipdcs = @('skipme')
    $searchbase = 'CN=Services,CN=configuration,dc=my,dc=domain,dc=here'
    $dcs = ((Get-ADObject -SearchBase $searchbase  -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" -Server $domain_controller).Where({ $_.distinguishedname -notlike '*\0ACNF*' -and $_.name -notin ($skipdcs) })).name
    $online = $dcs.Where({ Test-NetConnection -ComputerName $_ -InformationLevel quiet -WarningAction SilentlyContinue })


    $data = $online | ForEach-Object -ThrottleLimit 12 -Parallel {
        $server = $_
        $scopes = Get-DhcpServerv4Scope -ComputerName $server

        $leaseproperties = @(
            'ipaddress',
            'scopeid',
            'clientid',
            @{Name = 'clientmac'; Expression = { ($_.ClientId -match '^(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})$') ?  ($_.ClientId) : ($null) } },
            'hostname', 
            'addressstate', 
            'leaseexpirytime',
            @{name = 'DC'; expression = { $server } }
        )
        $leases = ($scopes | Select-Object @{Name = 'Object'; Expression = { Get-DhcpServerv4Lease -ScopeId $_.scopeid -ComputerName $server } }).Object | Select-Object -Property $leaseproperties
        $scopeinfo = $scopes | Select-Object scopeid, subnetmask, name, description, state, startrange, endrange, @{name = 'leaseduration'; expression = { $_.leaseduration.totalseconds } }, @{name = 'DC'; expression = { $server } } -ExcludeProperty leaseduration
        $scopeoptions = $scopes.foreach({
                $scopeid = $_.scopeid
                $properties = @(
                    @{Name = 'scopeid'; Expression = { $scopeid } },
                    @{name = 'DC'; expression = { $server } },
                    @{name = 'optionid'; expression = { [int]$_.optionid } },
                    'name',
                    'type',
                    @{Name = 'value'; Expression = { '{' + (($_.value) -join ',') + '}' } }
                )
                $_ | Get-DhcpServerv4OptionValue -ComputerName $server | Select-Object -Property $properties
            })
        
        [PSCustomObject]@{
            Scopes        = $scopeinfo
            Leases        = $leases
            Scope_Options = $scopeoptions
        }
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $data.scopes -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'dhcp_scopes' -Truncate $true
        Invoke-PGSqlQuery -Type Insert -InputObject $data.leases -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'dhcp_leases' -Truncate $true
        Invoke-PGSqlQuery -Type Insert -InputObject $data.scope_options -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'dhcp_scope_options' -Truncate $true

        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-ADDNSRecords {

    $dnszone = 'mydomain.com'
    $properties = @(
        'HostName',
        'RecordType',
        'Timestamp',
        # "RecordData",
        @{name = 'data'; expression = { $_.RecordData.IPv4Address } }
        @{name = 'zone'; expression = { $dnszone } }
    )

    $dnsproperties = @(
        'HostName',
        'RecordType',
        'Timestamp',
        @{name = 'RecordData'; expression = { $_.RecordData | Select-Object * -ExcludeProperty @('CimClass', 'PSComputerName', 'CimSystemProperties', 'CimInstanceProperties') | ConvertTo-Json -Compress -WarningAction SilentlyContinue } }
        @{name = 'zone'; expression = { $dnszone } }
    )
    
    $records = (Get-DnsServerResourceRecord -ComputerName $domain_controller -ZoneName $dnszone -RRType A) | Select-Object -Property $properties | Where-Object { $_.hostname -notin ('@', 'DomainDnsZones', 'ForestDnsZones') }
    $dnsrecords = Get-DnsServerResourceRecord -ComputerName $domain_controller -ZoneName $dnszone | Select-Object -Property $dnsproperties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $records -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'dns_a_records' -Truncate $true
        Invoke-PGSqlQuery -Type Insert -InputObject $dnsrecords -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'dns_records' -Truncate $true

        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Remove-ADInactiveComputerObjects {

    $disablequery = @'
    SELECT name, site, distinguishedname, operatingsystem, osmajorversion, osminorversion, ostype, enabled, description, lastlogondate
	FROM "ActiveDirectory".computers
    where ostype = 'Client' and lastlogondate < now() - interval '60 day' and enabled = 'True' and site not in ('Computers','Domain Controllers')
     and name not in (    SELECT member_name from  "ActiveDirectory".group_members('Cleanup-Exclusions') where member_class = 'computer')
    order by lastlogondate
'@

    $deletequery = @'
SELECT name, site, distinguishedname, operatingsystem, osmajorversion, osminorversion, ostype, enabled, description, lastlogondate
	FROM "ActiveDirectory".computers
    where ostype = 'Client' and  lastlogondate < now() - interval '90 day' and enabled = 'False' and site not in ('Computers','Domain Controllers')
    and name not in (    SELECT member_name from  "ActiveDirectory".group_members('Cleanup-Exclusions') where member_class = 'computer')
    order by lastlogondate  
'@


    $disable = Invoke-PGSqlQuery -Type Select -Query $disablequery
    $delete = Invoke-PGSqlQuery -Type Select -Query $deletequery

    foreach ($enabledcomputer in $disable) {
        #Disable-ADAccount -Identity $enabledcomputer.distinguishedname -Confirm:$false
    }

    foreach ($disabledcomputer in $delete) {
        #Remove-ADObject -Identity $disabledcomputer.distinguishedname -Confirm:$false
    }
}

Function Get-ADGroupPolicySecurity {

    $searchbase = 'CN=Policies,CN=System,DC=my,DC=domain,DC=here'
    $gpos = Get-ADObject -SearchBase $searchbase -Filter { objectClass -eq 'groupPolicyContainer' } -Server $domain_controller

    $objectsecurity = foreach ($gpo in $gpos) {
        $gpoObject = [ADSI]"LDAP://$($gpo.distinguishedName)"
        $properties = @(
            @{Name = 'GPO'; Expression = { $gpoObject.displayName } }
            @{Name = 'GPODN'; Expression = { $gpoObject.distinguishedName } }, 
            @{Name = 'ActiveDirectoryRights'; Expression = { '{' + (([string]$_.ActiveDirectoryRights).split(', ') -join ',') + '}' } }
            'ObjectType',
            @{Name = 'AccessControlType'; Expression = { [string]$_.AccessControlType } },
            @{Name = 'IdentityReference'; Expression = { [string]$_.IdentityReference } },
            @{Name = 'SID'; Expression = { [string]$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } }
        )
        $gpoObject.ObjectSecurity.Access | Select-Object -Property $properties
    }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $objectsecurity -OnConflict 'Do Nothing' -Schema 'ActiveDirectory' -Table 'grouppolicysecurity' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Invoke-ADScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    switch ($Schedule) {
        '15Minute' {
            Write-Output 'Get-ADUsers'; Get-ADUsers
            Write-Output 'Get-ADComputers'; Get-ADComputers 
            Write-Output 'Get-ADUserWorkstations'; Get-ADUserWorkstations
            
        }
        'Hourly' {
            Write-Output 'Get-ADGroupsAndMembers'; Get-ADGroupsAndMembers
            Write-Output 'Get-ADComputerVersionTotals'; Get-ADComputerVersionTotals
            Write-Output 'Get-ADServerVersionTotals'; Get-ADServerVersionTotals
            Write-Output 'Get-ADUserWorkstationsTotals'; Get-ADUserWorkstationsTotals
        }
        'Daily' {
            Write-Output 'Get-ADObjects'; Get-ADObjects
            Write-Output 'Get-ADSubnets'; Get-ADSubnets
            Write-Output 'Get-ADDNSRecords'; Get-ADDNSRecords
            Write-Output 'Get-ADDHCPScopes'; Get-ADDHCPScopes
            Write-Output 'Get-ADGroupPolicySecurity'; Get-ADGroupPolicySecurity
            #Write-Output "Remove-ADInactiveComputerObjects"; Remove-ADInactiveComputerObjects
        }
    }

}