Function Connect-Commvault {
    $useraccount = 'commvault_user'
    $password = Get-SecretFromVault -Vault $global:Vault -Name $useraccount
    try {
    Connect-CVServer -User $useraccount -Password $password -Server $commvault_commserve
    }
    catch{
        Write-Error -Message "Something went wrong, you probably don't have the commvault module installed. Make sure it's added to your powershell path too..."
    }
}


Function Get-CVClients {
    Connect-Commvault

    $Headers = @{
        AuthToken = $global:CVConnectionPool.token
        Accept    = 'application/json'
    }
    
    $url = "http://$commvault_commserve:81/SearchSvc/CVWebService.svc/Client"
    
    $result = Invoke-RestMethod -Method Get -Uri $url -Headers $Headers -ContentType 'application/json'
    
    $Properties = @(
        @{Name = 'id'; Expression = { $_.client.clientEntity.clientId } },
        @{Name = 'clientname'; Expression = { $_.client.clientEntity.clientname } },
        @{Name = 'isdeleted'; Expression = { if ($_.clientProps.IsDeletedClient) { 'True' } else { 'False' } } }
    )
    
    $clients = $result.clientProperties | Select-Object -Property $Properties
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $clients -OnConflict 'Do Nothing' -Schema 'commvault' -Table 'clients' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    Disconnect-CVServer
}
Function Get-CVReport {
    $Properties = @(
        'JobId',
        'Client',
        'ClientId',
        'Agent',
        'Instance',
        'BackupSet',
        'Subclient',
        'MediaAgent',
        @{name = 'vm_hypervisor_type'; expression = { $_.'VM HyperVisor Type' } },
        @{name = 'operation_type'; expression = { $_.'Operation Type' } },
        @{name = 'backup_type'; expression = { $_.' Backup Type' } },
        @{name = 'start_time'; expression = { [datetime]$_.'Start Time' } },
        @{name = 'end_time'; expression = { [datetime]$_.'End Time' } },
        @{name = 'duration'; expression = { $_.'Duration(mins)' } },
        @{name = 'size_of_application'; expression = { $_.'Size of Application' } },
        @{name = 'media_size'; expression = { $_.'Media Size' } },
        @{name = 'storage_policy'; expression = { $_.'Storage Policy' } },
        @{name = 'network_size'; expression = { $_.'Network Size' } },
        @{name = 'protected_objects'; expression = { $_.'Protected Objects' } },
        @{name = 'failed_objects'; expression = { $_.'Failed Objects' } },
        @{name = 'failed_folders'; expression = { $_.'Failed Folders' } },
        @{name = 'job_status'; expression = { $_.'Job Status' } },
        @{name = 'dedup_savings'; expression = { $_.'Dedup Savings(%)' } },
        @{name = 'client_group'; expression = { $_.'Client Group' } },
        @{name = 'failure_reason'; expression = { ($_.'Failure Reason').Replace('&lt;', '<').Replace('&gt;', '>') } },
        @{name = 'throughput'; expression = { $_.'Throughput (GB/Hour)' } },
        @{name = 'vm_backup_size'; expression = { $_.'VM Backup Size' } },
        @{name = 'vm_size'; expression = { $_.'VM Size' } },
        @{name = 'vm_guest_size'; expression = { $_.'VM Guest Size' } },
        @{name = 'proxy'; expression = { $_.'Proxy' } },
        @{name = 'vm_guest_tools'; expression = { $_.'VM Guest Tools' } },
        @{name = 'vm_transport_mode'; expression = { $_.'VM Transport Mode' } },
        @{name = 'vm_cbt_status'; expression = { $_.'VM CBT Status' } },
        @{name = 'vm_operating_system'; expression	= { $_.'VM Operating System' } },
        @{name = 'vm_guid'; expression = { $_.'VM GUID' } },
        @{name = 'vm_host'; expression = { $_.'VM Host' } },
        @{name = 'vm_datastore'; expression = { $_.'VM Datastore' } },
        @{name = 'virtualization_client'; expression	= { $_.'Virtualization Client' } },
        @{name = 'virtual_server'; expression = { $_.'Virtual Server' } }	
    )
    Connect-Commvault
    
    $header = @{Accept = 'application/json'; Authtoken = $CVConnectionpool.token }

    $uri = "uri from your commvault web console reports page. you should be able to get an API link right from the console..."
    
    $backupjobs = (Invoke-RestMethod -Uri $uri -Headers $header -Method get).records  | Select-Object -Property $Properties

    $vmbackups = $backupjobs | Where-Object { $_.vm_host -ne '' }
    $backups = $backupjobs | Where-Object { $_.vm_host -eq '' }

    if ($vmbackups) {
        Invoke-PGSqlQuery -Type Insert -InputObject $vmbackups -OnConflict 'Set Excluded' -Schema 'commvault' -Table 'vm_backup_jobs' -Truncate $false
    }
    if ($backups) {
        Invoke-PGSqlQuery -Type Insert -InputObject $backups -OnConflict 'Set Excluded' -Schema 'commvault' -Table 'backup_jobs' -Truncate $false
    }



  
    Disconnect-CVServer
}

Function Get-CVGroups {


    Connect-Commvault
    $header = @{Accept = 'application/json'; Authtoken = $CVConnectionpool.token }
    $uri = "uri from your commvault web console reports page. you should be able to get an API link right from the console..."
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method get

    $properties = @(
        @{Name = 'groupname'; Expression = { $_.ClientGroupName } },
        @{Name = 'groupid'; Expression = { $_.ClientGroupId } }
        'clientname'
    )
    $cvgroupmemberships = $response.records | Select-Object -Property $properties
        
    Invoke-PGSqlQuery -Type Truncate -Schema 'commvault' -Table 'client_site' -Truncate $true

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $cvgroupmemberships -OnConflict 'Do Nothing' -Schema 'commvault' -Table 'clientgroupmembership' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
    Disconnect-CVServer
}

Function Get-CVLicenseSummary {

    $properties = @(
        @{Name = 'License'; Expression = { $_.Dial } },
        'LicUsageType',
        'Purchased',
        'PermTotal',
        'Eval',
        'Usage',
        'EvalExpiryDate',
        'Summary'
    )

    $uri = "uri from your commvault web console reports page. you should be able to get an API link right from the console..."
    Connect-Commvault

    $header = @{Accept = 'application/json'; Authtoken = $CVConnectionpool.token }
    $data = Invoke-RestMethod -Uri $uri -Headers $header -Method get

    $inputobject = foreach ($record in $data.records) {

        $result = New-Object -TypeName PSObject
        for ($i = 0; $i -lt $data.columns.Length; $i++) {
            $result | Add-Member -MemberType NoteProperty -Name $data.columns[$i].Name -Value $record[$i]
        }
        $result
    } 

    Invoke-PGSqlQuery -Type Insert -InputObject ($inputobject | Select-Object -Property $properties) -OnConflict 'Set Excluded' -Schema 'commvault' -Table 'license_summary' -Truncate $true

    Disconnect-CVServer

}



Function Get-CommvaultVirtualMachines {

    $properties = @(
        'applicationsize',
        'bkpendtime',
        'bkpstarttime',
        @{Name = 'client'; Expression = { $_.client | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'commcell'; Expression = { $_.commcell | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'dcplan'; Expression = { $_.dcplan | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'instanceentity'; Expression = { $_.instanceentity | ConvertTo-Json -WarningAction SilentlyContinue } },
        'isbackupallowed',
        'iscontentindexded',
        'isdeleted',
        'isindexingv2',
        @{Name = 'lastbackupjobinfo'; Expression = { $_.lastbackupjobinfo | ConvertTo-Json -WarningAction SilentlyContinue } },
        'latestbackuptimecatalogedsuccessfully',
        'name',
        'ostype',
        @{Name = 'plan'; Expression = { $_.plan | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'proxyclient'; Expression = { $_.proxyclient | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'pseudoclient'; Expression = { $_.pseudoclient | ConvertTo-Json -WarningAction SilentlyContinue } },
        'retireclientphase',
        'slacategory',
        'slacategorydescription',
        'slastatus',
        'storagepolicyname',
        'strguid',
        'strosname',
        'subclientid',
        'subclientname',
        'type',
        'vendor',
        'vmagent',
        'vmbackupjob',
        'vmfailurereasonforwarning',
        'vmguestspace',
        'vmhardwarever',
        'vmhost',
        'vmsize',
        'vmstatus',
        'vmusedspace',
        @{Name = 'vsanextbackupsubcliententity'; Expression = { $_.vsanextbackupsubcliententity | ConvertTo-Json -WarningAction SilentlyContinue } },
        @{Name = 'vsasubcliententity'; Expression = { $_.vsasubcliententity | ConvertTo-Json -WarningAction SilentlyContinue } }
    )

    Connect-Commvault

    $VirtualMachines = Get-CVVirtualMachine | Select-Object -Property $properties

    Invoke-PGSqlQuery -Type Insert -InputObject $VirtualMachines -OnConflict 'Do Nothing' -Schema 'commvault' -Table 'virtualmachines' -Truncate $true


}
Function Invoke-CVScheduledFunction {
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
            Write-Output 'Get-CVReport'; Get-CVReport

            
        }
        'Daily' {
            Write-Output 'Get-CVClients'; Get-CVClients 
            Write-Output 'Get-CVGroups'; Get-CVGroups 
            Write-Output 'Get-CommvaultVirtualMachines'; Get-CommvaultVirtualMachines
            Write-Output 'Get-CVLicenseSummary'; Get-CVLicenseSummary
        }
    }

}


 







