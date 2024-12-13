
$switchsqltables = @{
    'Port - Index'                       = 'switches.portindex'
    'Port - Descriptions'                = 'switches.portdescriptions'
    'Port - Port Speed'                  = 'switches.portspeed'
    'Port - Admin Status'                = 'switches.portadmstatus'
    'Port - Operating Status'            = 'switches.portopstatus'
    'Port - Port Alias'                  = 'switches.portalias'
    'VLAN - VLAN Type'                   = 'switches.portvlantype'
    'VLAN - VLAN'                        = 'switches.portvlan'
    'VLAN - VLAN Name'                   = 'switches.vlanname'
    'VLAN - VLAN Index'                  = 'switches.vlanindex'
    'CDP - Version'                      = 'switches.cdp_version'
    'CDP - DeviceID'                     = 'switches.cdp_deviceid'
    'CDP - PortID'                       = 'switches.cdp_portid'
    'CDP - Platform'                     = 'switches.cdp_platform'
    'CDP - Capabilities'                 = 'switches.cdp_capabilities'
    'CDP - IP'                           = 'switches.cdp_ip'
    'IP - Index'                         = 'switches.ip_index'
    'IP - NetMask'                       = 'switches.ip_netmask'
    'LLDP - ChassisIdSubtype'            = 'switches.lldpchassisidsubtype'
    'LLDP - ChassisId'                   = 'switches.lldpchassisid'
    'LLDP - PortIdSubtype'               = 'switches.lldpportidsubtype'
    'LLDP - PortId'                      = 'switches.lldpportid'
    'LLDP - PortDescription'             = 'switches.lldpportdescription'
    'LLDP - SystemName'                  = 'switches.lldpsystemname'
    'LLDP - SystemDescription'           = 'switches.lldpsystemdescription'
    'LLDP - CapabilitiesMapSupported'    = 'switches.lldpcapabilitiesmapsupported'
    'LLDP - CacheCapabilities'           = 'switches.lldpcachecapabilities'
    'LLDP - LocPortId'                   = 'switches.lldplocportid'   
    'LLDP - LocPortDesc'                 = 'switches.lldplocportdesc' 
    '802.1x - cpaePortMode'              = 'switches.cpaeportmode'
    '802.1x - cpaePortOperVlan'          = 'switches.cpaeportopervlan'
    '802.1x - cpaePortOperVlanType'      = 'switches.cpaeportopervlantype'
    'Entity - entPhysicalClass'          = 'switches.entphysicalclass'
    'Entity - entPhysicalName'           = 'switches.entphysicalname'
    'Entity - entAliasMappingIdentifier' = 'switches.entaliasmappingidentifier'
    'Interface - ifName'                 = 'switches.ifname'
    'MAC - dot1dTpFdbPort'               = 'switches.dot1dtpfdbport'
    'MAC - dot1dBasePortIfIndex'         = 'switches.dot1dbaseportifindex'
}

function Get-SnmpData {

 
    [CmdletBinding()]
    param (
        # Endpoint IP address.
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Endpoint IP address'
        )]
        [Net.IPAddress]$IP,
    
        # OID list.
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'OID list'
        )]
        [string[]]$OID,
        
        # SNMP Community.
        [string]$Community = 'public', 
        
        # SNMP port.
        [int]$UDPport = 161,
    
        # SNMP version.
        [Lextm.SharpSnmpLib.VersionCode]$Version = 'V2',
    
        # Time out value.    
        [int]$TimeOut = 3000
    )

    $ErrorActionPreference = 'Stop'
    $list = [Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()
    $list.Add([Lextm.SharpSnmpLib.Variable]::new([Lextm.SharpSnmpLib.ObjectIdentifier]::new($OID)))

    $endpoint = New-Object Net.IpEndPoint $IP, $UDPport
     
    try {
        $message = [Lextm.SharpSnmpLib.Messaging.Messenger]::Get(
            $Version, 
            $endpoint, 
            $Community, 
            $list, 
            $TimeOut
        )
    }
    catch {
        Write-Error -Exception $_.Exception
        throw
    }
     
    foreach ($variable in $message) {
        New-Object PSObject -Property @{
            OID  = $variable.Id.ToString()
            Data = $variable.Data.ToString()
        }
    }
}


function Invoke-SNMPv2BulkWalk {
    param(
        [Parameter(Mandatory = $true)] [String] $Community,
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Endpoint IP address'
        )]
        [Net.IPAddress]$IP,
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'OID of root object'
        )]
        [string[]]$OIDStart,
        [int]$UDPport = 161,
        [int]$TimeOut = 10000,
        [int]$MaxRepetitions = 10,
        [Parameter(Mandatory = $True)]
        [ValidateSet(
            'String',
            'Hex')]
        [string]$Format,
        [Lextm.SharpSnmpLib.VersionCode]$Version = 'V2',
        [ValidateSet('Default', 'WithinSubTree')]
        [Lextm.SharpSnmpLib.Messaging.WalkMode]$WalkMode = 'WithinSubTree'
    )

 
    $endPoint = New-Object System.Net.IPEndPoint($IP, $UDPPort)


    $results = New-Object System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]

 
    [void][Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk($Version,
        $endPoint,
        [Lextm.SharpSnmpLib.OctetString]::new($Community),
        $null,
        [Lextm.SharpSnmpLib.ObjectIdentifier]::new("$OIDStart"),
        $results,
        $timeout,
        $MaxRepetitions,
        $WalkMode,
        $null,
        $null
    )
 
    # Return the SNMP data

    if ($Format -eq 'String') {
        foreach ($variable in $results) {
            New-Object PSObject -Property @{
                OID  = $variable.Id.ToString()
                Data = $variable.Data.ToString()
            }
        }
    }
    if ($Format -eq 'Hex') {
        foreach ($variable in $results) {
            New-Object PSObject -Property @{
                OID  = $variable.Id.ToString()
                Data = $variable.Data.ToHexString()
            }
        }
    } 
}

function ConvertFrom-CDPCapabilityBits {
    param (
        [string]$CapabilitiesHex
    )

    if ($CapabilitiesHex -ne '00020000') {
        $Capabilities = [convert]::ToInt32($CapabilitiesHex, 16)


        $CapabilityBits = @{
            'Router'                  = 0x01
            'Transparent-Bridge'      = 0x02
            'Source-Route-Bridge'     = 0x04
            'Switch'                  = 0x08
            'Host'                    = 0x10
            'IGMP Snooping'           = 0x20
            'Repeater'                = 0x40
            'VoIP Phone'              = 0x80
            'Remotely-Managed Device' = 0x100
        }
                
        [System.Collections.ArrayList]$CapabilitiesArray = @()
        foreach ($Capability in $CapabilityBits.Keys) {
            if (($Capabilities -band $CapabilityBits[$Capability]) -ne 0) {
                [void]$CapabilitiesArray.Add($Capability)
            }
        }
        return $CapabilitiesArray
    }
    else {
        return 'Transparent Repeater'
    }
}

function ConvertFrom-CDPIPHex {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $false,
            Position = 0)]
        $IPHEX
    )
    Process {
        if ($iphex.length -eq 0) {
            $ReturnValue += '0.0.0.0'
        }
        if ($iphex.length -eq 8) {
            $ReturnValue += ($iphex -split '(..)' -ne '' | ForEach-Object { [uint32]"0x$_" }) -join '.'
        }
        if ($IPHEX.Length -eq 32) {
            $ReturnValue += ($iphex -split '(....)' -ne '') -join ':'
        }
    }
    End {
        return $ReturnValue
    }
}

function ConvertFrom-LLDPCapability {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $false,
            Position = 0)]
        $ClientIntentValue
    )
 
    Begin {
        $ReturnValue = @()
        $ClientIntentHash = @{
            'Other'             = 128
            'Repeater'          = 64
            'Bridge'            = 32
            'WLANAccessPoint'   = 16
            'Router'            = 8
            'Telephone'         = 4
            'DocsisCableDevice' = 2
            'StationOnly'       = 1
        }
    }
    Process {
        foreach ($Bit in ($ClientIntentHash.GetEnumerator() | Sort-Object -Property Value )) {
            if (($ClientIntentValue -band $Bit.Value) -ne 0) {
                $ReturnValue += $Bit.Key
            }
        }
    }
    End {
        return $ReturnValue
    }
}

function ConvertFrom-EntityClass {
    [CmdletBinding()]
    [Alias()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $false,
            Position = 0)]
        $entityclass
    )
    begin {
        $entityclasshash = @{
            '1'  = 'other'
            '2'  = 'unknown'
            '3'  = 'chassis'
            '4'  = 'backplane'
            '5'  = 'container'
            '6'  = 'powerSupply'
            '7'  = 'fan'
            '8'  = 'sensor'
            '9'  = 'module'
            '10' = 'port'
            '11' = 'stack'
            '12' = 'cpu'
        }
    }
    Process {
        return $entityclasshash["$entityclass"]
    }
}

Function Get-SwitchSNMPData {
    <#
    .SYNOPSIS
        Retrieves SNMP data from a switch and writes it to a Postgresql table. Tested only on Cisco switches but should be flexible enough to work with other vendors.
    .DESCRIPTION
       Requires an IP and community string. 
    .NOTES
        This function does a basic check of the sysDescr oid (1.3.6.1.2.1.1.1.0) to make sure the device can be reached before attempting to pull more data.

        Use -DebugScan $true for seeing what data gets returned. You can also view the input object that would get written to the DB (use this for adding a table with Add-PgSQLTable)
    .EXAMPLE
        Get-SwitchSNMPData -DataType All -IP 192.168.1.1 -Community 'public'

    .EXAMPLE
        For Example, if the table doesn't exist
        $test = Get-SwitchSNMPData -DataType 'Port - Descriptions' -IP 192.168.1.1 -Community 'public' -DebugScan $true
        $test.Exception

        System.Management.Automation.MethodInvocationException: Exception calling "Fill" with "1" argument(s): "ERROR [42P01] ERROR: relation "switches.portdescriptions" does not exist;

        Create the table:
        Add-PGSQLTable -InputObject $test.inputobject -Table portdescriptions -Schema switches -PrimaryKeys @("ifindex","ip") -GrantReadOnly -ReadOnlyGroup "readonly"

        CREATE TABLE switches.portdescriptions
(
data text, ifindex integer NOT NULL, ip inet NOT NULL,
CONSTRAINT portdescriptions_pkey PRIMARY KEY (ifindex,ip)
)
switches.portdescriptions - Created Successfully
switches.portdescriptions - Granted Select to readonly
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [ValidateSet(
            'Port - Index',
            'Port - Descriptions',
            'Port - Port Speed',
            'Port - Admin Status',
            'Port - Operating Status',
            'Port - Port Alias',
            'VLAN - VLAN Type',
            'VLAN - VLAN',
            'VLAN - VLAN Name',
            'VLAN - VLAN Index',
            'CDP - Version',
            'CDP - DeviceID',
            'CDP - PortID',
            'CDP - Platform',
            'CDP - Capabilities',
            'CDP - IP',
            'IP - Index',
            'IP - NetMask',
            'LLDP - ChassisIdSubtype',
            'LLDP - ChassisId',
            'LLDP - PortIdSubtype',
            'LLDP - PortId',
            'LLDP - PortDescription',
            'LLDP - SystemName',
            'LLDP - SystemDescription',
            'LLDP - CapabilitiesMapSupported',
            'LLDP - CacheCapabilities',
            'LLDP - LocPortId',
            'LLDP - LocPortDesc',
            '802.1x - cpaePortMode',
            '802.1x - cpaePortOperVlan',
            '802.1x - cpaePortOperVlanType',
            'Entity - entPhysicalClass',
            'Entity - entPhysicalName',
            'Entity - entAliasMappingIdentifier',
            'Interface - ifName',
            'All'
        )]
        [string]$DataType,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$IP,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$Community,
        [Parameter(Mandatory = $false)]
        [bool]$DebugScan,
        [Parameter(Mandatory = $false)]
        [bool]$DeleteOnly = $false,
        [Parameter(Mandatory = $false)]
        [bool]$InsertOnly = $false,
        [Parameter(Mandatory = $false)]
        [string]$DataTypeRegex

    )




    $AllDataTypes = @(
        'Port - Index',
        'Port - Descriptions',
        'Port - Port Speed',
        'Port - Admin Status',
        'Port - Operating Status',
        'Port - Port Alias'
        'VLAN - VLAN Type',
        'VLAN - VLAN',
        'VLAN - VLAN Name',
        'VLAN - VLAN Index'
        'CDP - Version',
        'CDP - DeviceID',
        'CDP - PortID',
        'CDP - Platform',
        'CDP - Capabilities',
        'CDP - IP',
        'IP - Index',
        'IP - NetMask',
        'LLDP - ChassisIdSubtype',
        'LLDP - ChassisId',
        'LLDP - PortIdSubtype',
        'LLDP - PortId',
        'LLDP - PortDescription',
        'LLDP - SystemName',
        'LLDP - SystemDescription',
        'LLDP - CapabilitiesMapSupported',
        'LLDP - CacheCapabilities',
        'LLDP - LocPortId',
        'LLDP - LocPortDesc',
        '802.1x - cpaePortMode',
        '802.1x - cpaePortOperVlan',
        '802.1x - cpaePortOperVlanType',
        'Entity - entPhysicalClass',
        'Entity - entPhysicalName',
        'Entity - entAliasMappingIdentifier',
        'Interface - ifName'
    )
    
    if ($DataType -eq 'All') {
        if ($DataTypeRegex) {
            $DataScans = $AllDataTypes | Where-Object { $_ -Match "($DataTypeRegex) \- .*" }
        }
        else {
            $DataScans = $AllDataTypes
        }
    }
    else { $DataScans = $DataType }
    
    try {
        $check = (Get-SnmpData -IP $ip -OID '1.3.6.1.2.1.1.1.0' -Community $community -Version V2 -TimeOut 5000 -ErrorAction SilentlyContinue).data
    }
    catch {
        $status = 'Check Failed'
        $exception = $_.Exception
    }
    
    if ($null -ne $check) {
    
    
    
        $CDPCapabilitiesProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{name = 'neighborindex'; expression = { ($_.oid).split('.')[-1] } },
            @{name = 'data'; expression = { '{' + ((ConvertFrom-CDPCapabilityBits -CapabilitiesHex $_.data) -join ',') + '}' } },
            @{name = 'ip'; expression = { [ipaddress]"$IP" } }  
        )
        
    
        $CDPIPProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{name = 'neighborindex'; expression = { ($_.oid).split('.')[-1] } },
            @{name = 'data'; expression = { ConvertFrom-CDPIPHex -IPHEX $_.data } }, 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $CDPDefaultProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{name = 'neighborindex'; expression = { ($_.oid).split('.')[-1] } },
            'data', 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $IPIndexProperties = @(
            @{name = 'ifindex'; expression = { $_.data } }, 
            @{name = 'data'; expression = { $_.OID.Replace("$($SNMPMappings.item("$DataType").OID).", '') } }, 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
    
        $IPNetMaskProperties = @(
            @{name = 'ifindex'; expression = { $_.OID.Replace("$($SNMPMappings.item("$DataType").OID).", '') } }, 
            'data', 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $PortDefaultProperties = @(
            @{name = 'ifindex'; expression = { $_.OID.Split('.')[-1] } }, 
            'data', 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $LLDPProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{name = 'neighborindex'; expression = { ($_.oid).split('.')[-1] } },
            @{Name = 'data'; Expression = { if ($_.data -match '.*\?.*') { [String]::Join('', ([System.Text.Encoding]::ASCII.GetBytes($_.data) | ForEach-Object { '{0:X2}' -f $_ })) } else { $_.data -replace '[^\x21-\x7e]+', '' } } }, 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $LLDPHexProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{name = 'neighborindex'; expression = { ($_.oid).split('.')[-1] } },    
            @{name = 'data'; expression = { '{' + ((ConvertFrom-LLDPCapability -ClientIntentValue ('0x' + $_.data.SubString(0, 2))) -join ',') + '}' } }, 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
            
        $entPhysicalClassProperties = @(
            @{name = 'ifindex'; expression = { $_.OID.Split('.')[-1] } }, 
            @{name = 'data'; expression = { ConvertFrom-EntityClass -entityclass $_.data } }, 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $entAliasMappingIdentifierProperties = @(
            @{name = 'ifindex'; expression = { ($_.oid).split('.')[-2] } },
            @{Name = 'data'; Expression = { $_.data.split('.')[-1] } } , 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
        $VLANDefaultProperties = @(
            @{name = 'vlanindex'; expression = { $_.OID.Split('.')[-1] } }, 
            'data', 
            @{name = 'ip'; expression = { [ipaddress]"$IP" } } 
        )
    
    
        $PortIndex = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.2.2.1.1'; Schema = 'switches'; Table = 'portindex'; Format = 'string' }
        $PortDescriptions = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.2.2.1.2'; Schema = 'switches'; Table = 'portdescriptions'; Format = 'string' }
        $PortPortSpeed = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.2.2.1.5'; Schema = 'switches'; Table = 'portspeed'; Format = 'string' }
        $PortAdminStatus = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.2.2.1.7'; Schema = 'switches'; Table = 'portadmstatus'; Format = 'string' }
        $PortOperatingStatus = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.2.2.1.8'; Schema = 'switches'; Table = 'portopstatus'; Format = 'string' }
        $PortPortAlias = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.31.1.1.1.18'; Schema = 'switches'; Table = 'portalias'; Format = 'string' }
        $VLANVLANType = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.4.1.9.9.68.1.2.2.1.1'; Schema = 'switches'; Table = 'portvlantype'; Format = 'string' }
        $VLANVLAN = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'; Schema = 'switches'; Table = 'portvlan'; Format = 'string' }
        $VLANVLANName = [PSCustomObject]@{Properties = $VLANDefaultProperties; OID = '1.3.6.1.4.1.9.9.46.1.3.1.1.4.1'; Schema = 'switches'; Table = 'vlanname'; Format = 'string' }
        $VLANVLANIndex = [PSCustomObject]@{Properties = $VLANDefaultProperties; OID = '1.3.6.1.4.1.9.9.46.1.3.1.1.18.1'; Schema = 'switches'; Table = 'vlanindex'; Format = 'string' }
        $CDPVersion = [PSCustomObject]@{Properties = $CDPDefaultProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.5'; Schema = 'switches'; Table = 'cdp_version'; Format = 'string' }
        $CDPDeviceID = [PSCustomObject]@{Properties = $CDPDefaultProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'; Schema = 'switches'; Table = 'cdp_deviceid'; Format = 'string' }
        $CDPPortID = [PSCustomObject]@{Properties = $CDPDefaultProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'; Schema = 'switches'; Table = 'cdp_portid'; Format = 'string' }
        $CDPPlatform = [PSCustomObject]@{Properties = $CDPDefaultProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.8'; Schema = 'switches'; Table = 'cdp_platform'; Format = 'string' }
        $CDPCapabilities = [PSCustomObject]@{Properties = $CDPCapabilitiesProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.9'; Schema = 'switches'; Table = 'cdp_capabilities'; Format = 'hex' }
        $CDPIP = [PSCustomObject]@{Properties = $CDPIPProperties; OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'; Schema = 'switches'; Table = 'cdp_ip'; Format = 'hex' }
        $IPIndex = [PSCustomObject]@{Properties = $IPIndexProperties; OID = '1.3.6.1.2.1.4.20.1.2'; Schema = 'switches'; Table = 'ip_index'; Format = 'string' }
        $IPNetMask = [PSCustomObject]@{Properties = $IPNetMaskProperties; OID = '1.3.6.1.2.1.4.20.1.3'; Schema = 'switches'; Table = 'ip_netmask'; Format = 'string' }
        $LLDPChassisIdSubtype = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.4'; Schema = 'switches'; Table = 'lldpchassisidsubtype'; Format = 'string' }
        $LLDPChassisId = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.5'; Schema = 'switches'; Table = 'lldpchassisid'; Format = 'hex' }
        $LLDPPortIdSubtype = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.6'; Schema = 'switches'; Table = 'lldpportidsubtype'; Format = 'string' }
        $LLDPPortId = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.7'; Schema = 'switches'; Table = 'lldpportid'; Format = 'string' }
        $LLDPPortDescription = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.8'; Schema = 'switches'; Table = 'lldpportdescription'; Format = 'string' }
        $LLDPSystemName = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.9'; Schema = 'switches'; Table = 'lldpsystemname'; Format = 'string' }
        $LLDPSystemDescription = [PSCustomObject]@{Properties = $LLDPProperties; OID = '1.0.8802.1.1.2.1.4.1.1.10'; Schema = 'switches'; Table = 'lldpsystemdescription'; Format = 'string' }
        $LLDPCapabilitiesMapSupported = [PSCustomObject]@{Properties = $LLDPHexProperties; OID = '1.0.8802.1.1.2.1.4.1.1.11'; Schema = 'switches'; Table = 'lldpcapabilitiesmapsupported'; Format = 'hex' }
        $LLDPCacheCapabilities = [PSCustomObject]@{Properties = $LLDPHexProperties; OID = '1.0.8802.1.1.2.1.4.1.1.12'; Schema = 'switches'; Table = 'lldpcachecapabilities'; Format = 'hex' }
        $LLDPLocPortId = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.0.8802.1.1.2.1.3.7.1.3'; Schema = 'switches'; Table = 'lldplocportid'   ; Format = 'string' }
        $LLDPLocPortDesc = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.0.8802.1.1.2.1.3.7.1.4'; Schema = 'switches'; Table = 'lldplocportdesc' ; Format = 'string' }
        $8021xcpaePortMode = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.4.1.9.9.220.1.1.1.2'; Schema = 'switches'; Table = 'cpaeportmode'; Format = 'string' }
        $8021xcpaePortOperVlan = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.4.1.9.9.220.1.1.1.7'; Schema = 'switches'; Table = 'cpaeportopervlan'; Format = 'string' }
        $8021xcpaePortOperVlanType = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.4.1.9.9.220.1.1.1.8'; Schema = 'switches'; Table = 'cpaeportopervlantype'; Format = 'string' }
        $entPhysicalClass = [PSCustomObject]@{Properties = $entPhysicalClassProperties; OID = '1.3.6.1.2.1.47.1.1.1.1.5'; Schema = 'switches'; Table = 'entphysicalclass'; Format = 'string' }
        $entPhysicalName = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.47.1.1.1.1.7'; Schema = 'switches'; Table = 'entphysicalname'; Format = 'string' }
        $entAliasMappingIdentifier = [PSCustomObject]@{Properties = $entAliasMappingIdentifierProperties; OID = '1.3.6.1.2.1.47.1.3.2.1.2'; Schema = 'switches'; Table = 'entaliasmappingidentifier'; Format = 'string' }
        $ifName = [PSCustomObject]@{Properties = $PortDefaultProperties; OID = '1.3.6.1.2.1.31.1.1.1.1'; Schema = 'switches'; Table = 'ifname'; Format = 'string' }
        
    
        $SNMPMappings = @{
            'Port - Index'                       = $PortIndex
            'Port - Descriptions'                = $PortDescriptions
            'Port - Port Speed'                  = $PortPortSpeed
            'Port - Admin Status'                = $PortAdminStatus
            'Port - Operating Status'            = $PortOperatingStatus
            'Port - Port Alias'                  = $PortPortAlias
            'VLAN - VLAN Type'                   = $VLANVLANType
            'VLAN - VLAN'                        = $VLANVLAN
            'VLAN - VLAN Name'                   = $VLANVLANName
            'VLAN - VLAN Index'                  = $VLANVLANIndex
            'CDP - Version'                      = $CDPVersion
            'CDP - DeviceID'                     = $CDPDeviceID
            'CDP - PortID'                       = $CDPPortID
            'CDP - Platform'                     = $CDPPlatform
            'CDP - Capabilities'                 = $CDPCapabilities
            'CDP - IP'                           = $CDPIP
            'IP - Index'                         = $IPIndex
            'IP - NetMask'                       = $IPNetMask
            'LLDP - ChassisIdSubtype'            = $LLDPChassisIdSubtype
            'LLDP - ChassisId'                   = $LLDPChassisId
            'LLDP - PortIdSubtype'               = $LLDPPortIdSubtype
            'LLDP - PortId'                      = $LLDPPortId
            'LLDP - PortDescription'             = $LLDPPortDescription
            'LLDP - SystemName'                  = $LLDPSystemName
            'LLDP - SystemDescription'           = $LLDPSystemDescription
            'LLDP - CapabilitiesMapSupported'    = $LLDPCapabilitiesMapSupported
            'LLDP - CacheCapabilities'           = $LLDPCacheCapabilities
            'LLDP - LocPortId'                   = $LLDPLocPortId
            'LLDP - LocPortDesc'                 = $LLDPLocPortDesc
            '802.1x - cpaePortMode'              = $8021xcpaePortMode
            '802.1x - cpaePortOperVlan'          = $8021xcpaePortOperVlan
            '802.1x - cpaePortOperVlanType'      = $8021xcpaePortOperVlanType
            'Entity - entPhysicalClass'          = $entPhysicalClass
            'Entity - entPhysicalName'           = $entPhysicalName
            'Entity - entAliasMappingIdentifier' = $entAliasMappingIdentifier
            'Interface - ifName'                 = $ifName
        }
    
        $results = foreach ($datatype in $DataScans) {
    
    
            $data = $null
            $inputobject = $null
            $Exception = $null
    
            try {
                $data = Invoke-SNMPv2BulkWalk -IP $IP -OIDStart $SNMPMappings.item("$DataType").OID -Community $Community -Format $SNMPMappings.item("$DataType").Format -TimeOut 120000
                if ($data) {
                    $inputobject = $data | Select-Object -Property $SNMPMappings.item("$DataType").Properties 
                    $Status = 'Success'
                }
                else {
                    $status = 'No Data'
                }
            }
            catch {
                $Status = 'Fail'
                $Exception = $_.Exception
            }
    
            [PSCustomObject]@{
                IP          = $IP
                DataType    = $DataType
                OIDStart    = $SNMPMappings.item("$DataType").OID
                Format      = $SNMPMappings.item("$DataType").Format
                Community   = $Community
                Schema      = $SNMPMappings.item("$DataType").Schema
                Table       = $SNMPMappings.item("$DataType").Table 
                Status      = $status
                InputObject = $inputobject
                Exception   = $Exception
            }
        }
        
    
        foreach ($result in $results) {
            if ($result.InputObject) {
                try {
                    if ($InsertOnly -ne $true) {
                        Invoke-PGSqlQuery -Type Select -Query "DELETE FROM $($result.Schema).$($result.Table) WHERE ip = '$($result.IP)'" 
                    }
                    if ($InsertOnly -eq $false -and $DeleteOnly -eq $false) {
                        Invoke-PGSqlQuery -Type Insert -InputObject $result.InputObject -Schema $result.Schema -Table $result.Table -OnConflict 'Set Excluded' -Truncate $false
                    }
                }
                catch {
                    $result.status = 'Error'
                    $result.Exception = $_.Exception
                }
            }
            else {
                $result.Status = 'No InputObject'
            }
        }
        if ($DebugScan) {
            return $results 
        }
    }

    
}

Function Get-SwitchMACTable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [ValidateSet(
            'MAC - dot1dTpFdbPort',
            'MAC - dot1dBasePortIfIndex',
            'All')]
        [string]$DataType,
        [Parameter(Mandatory = $True)]
        [string]$IP,
        [Parameter(Mandatory = $True)]
        [string]$Community,
        [Parameter(Mandatory = $false)]
        [bool]$DebugScan,
        [Parameter(Mandatory = $false)]
        [bool]$DeleteOnly = $false,
        [Parameter(Mandatory = $false)]
        [bool]$InsertOnly = $false
    )


    $AllDataTypes = @(
        'MAC - dot1dTpFdbPort',
        'MAC - dot1dBasePortIfIndex'
    )
    
    if ($DataType -eq 'All') {
        $DataScans = $AllDataTypes
    }
    else { $DataScans = $DataType }
   
    $MACResults = foreach ($Datatype in $DataScans) {
        $vlans = $null
        $vlans = (Invoke-PGSqlQuery -Type Select -Query "select vlanindex from switches.vlanindex where ip = '$ip' and vlanindex < 1002 order by vlanindex").Vlanindex
        foreach ($vlan in $VLANs) {

            $MACMappings = $null
            $CommunityVLAN = $null
            $data = $null
            $inputobject = $null
            $Exception = $null

            $dot1dTpFdbPortproperties = @(
                @{name = 'index'; expression = { $_.data } }, 
                @{name = 'vlan'; expression = { "$vlan" } }, 
                @{name = 'data'; expression = { (($_.OID.Replace("$($MACMappings.Item("$DataType").OID).", '').Split('.') | ForEach-Object { [System.String]::Format('{0:X2}', [int]$_) }) -join ':').ToUpper() } }, 
                @{name = 'ip'; expression = { "$IP" } }
            )
    
            $dot1dBasePortIfIndexProperties = @(
                @{name = 'index'; expression = { $_.OID.Replace("$($MACMappings.Item("$DataType").OID).", '') } },
                @{name = 'ifindex'; expression = { $_.data } },
                @{name = 'vlan'; expression = { "$vlan" } },
                @{name = 'ip'; expression = { "$IP" } }
            )
    
            $dot1dTpFdbPort = [PSCustomObject]@{Properties = $dot1dTpFdbPortProperties; OID = '1.3.6.1.2.1.17.4.3.1.2'; Schema = 'switches'; Table = 'dot1dtpfdbport'; Format = 'string' }
            $dot1dBasePortIfIndex = [PSCustomObject]@{Properties = $dot1dBasePortIfIndexProperties; OID = '1.3.6.1.2.1.17.1.4.1.2'; Schema = 'switches'; Table = 'dot1dbaseportifindex'; Format = 'string' }
    
            $MACMappings = @{
                'MAC - dot1dTpFdbPort'       = $dot1dTpFdbPort
                'MAC - dot1dBasePortIfIndex' = $dot1dBasePortIfIndex
            }
            $CommunityVLAN = "$Community@$vlan" 
    


            try {
                $data = Invoke-SNMPv2BulkWalk -IP $IP -OIDStart $MACMappings.Item("$DataType").OID -Community $CommunityVLAN -Version V2 -Format $MACMappings.Item("$DataType").Format -ErrorAction SilentlyContinue -TimeOut 60000
                if ($data) {
                    $inputobject = $data | Select-Object -Property $MACMappings.Item("$DataType").Properties
                    $status = 'Success'
                }
                else {
                    $status = 'No MAC Addresses Found'
                }
      
            }
            catch {
                $Status = 'Fail'
                $Exception = $_.Exception
            }
            [PSCustomObject]@{
                IP          = $IP
                DataType    = $DataType
                OIDStart    = $MACMappings.Item("$DataType").OID
                Format      = $MACMappings.Item("$DataType").Format
                Community   = $Community
                Schema      = $MACMappings.item("$DataType").Schema
                Table       = $MACMappings.Item("$DataType").Table 
                InputObject = $inputobject
                Status      = $status
                Exception   = $Exception
                VLAN        = $vlan
            }
            
        }
               
    }
    $groups = $null
    $groups = $macresults | Where-Object {$_.InputObject} | Group-Object -Property schema, table
    
    foreach ($group in $groups) {
        $inputobject = $null
        $schema = $null
        $table = $null
        $switchip = $null

        $schema = $group.group[0].schema
        $table = $group.group[0].table
        $switchip = $group.group[0].ip
    
        $inputobject = $group.Group.InputObject
        if ($inputobject) {
            try {
                if ($InsertOnly -ne $true) {
                    Invoke-PGSqlQuery -Type Select -Query "DELETE FROM $($schema).$($table) WHERE ip = '$($switchip)'" 
                }
                if ($InsertOnly -eq $false -and $DeleteOnly -eq $false) {
                    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema $schema -Table $table -OnConflict 'Set Excluded' -Truncate $false
                }
            }
            catch {
                $_.Exception
            }   
        }
    }
    if ($DebugScan) {
        $MACResults | Sort-Object -Property vlan
    }
     
}

Function Remove-MissingSwitches {

    [CmdletBinding()]
    param (
        [Parameter()]
        $List
    )


    $iplist = foreach ($ip in $list.ip) {
        "'$ip'"
    }
    $in = '(' + ($iplist -join ',') + ')'

    foreach ($table in $switchsqltables.GetEnumerator()) {
        try {
            Invoke-PGSqlQuery -Type Select -Query "delete from $($table.value)  where ip not in $in"
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }

}


Function Get-SwitchSNMPInformation {
    $switches_query = @'
SELECT distinct(hostname)
	FROM switches.switch_info
	order by hostname
'@
    $switches = Invoke-PGSqlQuery -Type Select -Query $switches_query

    $list = @()
    foreach ($switch in $switches) {
        $list += Resolve-DnsName -Name $switch.hostname -Server $domain_controller -ErrorAction SilentlyContinue | Select-Object -Property @{name = 'ip'; expression = { $_.ipaddress } }, @{Name = 'hostname'; Expression = { $switch.hostname } } 
    }

    Remove-MissingSwitches -List $list

    $List | ForEach-Object -ThrottleLimit 16 -Parallel {
        $switch = $_
        $ip = $switch.ip
        Get-SwitchSNMPData -DataType All -IP $ip -Community 'snmp_community'
        Get-SwitchMACTable -DataType All -IP $ip -Community 'snmp_community'
    } 
    
}

Function Get-SwitchInfoCSV {

    $csv = Import-Csv -Path $pwd\Inbox\Ansible_Export\all_cisco_switch_ios_information.csv

    $properties = @(
        @{name = 'hostname'; expression = { $_.hostname } },
        @{name = 'switch_number'; expression = { [int]$_.switch_number } },
        @{name = 'actual_model'; expression = { $_.actual_model } },
        @{name = 'serial'; expression = { $_.serial } },
        @{name = 'model_group'; expression = { $_.model_group } },
        @{name = 'is_stack'; expression = { $_.is_stack } },
        @{name = 'current_version'; expression = { $_.current_version } },
        @{name = 'target_ver'; expression = { $_.target_ver } },
        @{name = 'at_latest'; expression = { $_.at_latest } },
        @{name = 'current_ios_image_file'; expression = { $_.current_ios_image_file } },
        @{name = 'total_flash'; expression = { $_.total_flash } },
        @{name = 'free_flash'; expression = { [long]$_.free_flash } },
        @{name = 'firmware_size'; expression = { [long]$_.firmware_size } },
        @{name = 'firware_filename'; expression = { $_.firware_filename } },
        @{name = 'firmware_hash'; expression = { $_.firmware_hash } },
        @{name = 'md5_hash_valid'; expression = { $_.md5_hash_valid } },
        @{name = 'vlan1_ip'; expression = { $_.vlan1_ip } },
        @{name = 'vlan900_ip'; expression = { $_.vlan900_ip } },
        @{name = 'ntp_synced'; expression = { $_.ntp_synced } },
        @{name = 'std_user_cfg'; expression = { $_.std_user_cfg } },
        @{name = 'num_users'; expression = { [int]$_.num_users } },
        @{name = 'last_update'; expression = { [datetime]$_.last_update.Insert(4, '-').Insert(7, '-') } },
        @{name = 'snmp_loc'; expression = { $_.snmp_loc } },
        @{name = 'soft_mode'; expression = { $_.soft_mode } },
        @{name = 'soft_ver'; expression = { $_.soft_ver } },
        @{name = 'bootloader_ver'; expression = { $_.bootloader_ver } },
        @{name = 'def_gw_ip'; expression = { $_.def_gw_ip } },
        @{name = 'dot1x_ready'; expression = { $_.dot1x_ready } },
        @{name = 'lldp_enabled'; expression = { $_.lldp_enabled } },
        @{name = 'cdp_enabled'; expression = { $_.cdp_enabled } },
        @{name = 'fw_pushed'; expression = { $_.fw_pushed } },
        @{name = 'web_enabled'; expression = { $_.web_enabled } },
        @{name = 'ssh_ver'; expression = { $_.ssh_ver } },
        @{name = 'dh_bits'; expression = { $_.dh_bits } },
        @{name = 'modulus_bits'; expression = { $_.modulus_bits } }
    )

    $inputobject = $csv | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'switches' -Table 'switch_info' -Truncate $true 
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-SwitchLinkHistory {
    $password = Get-SecretFromVault -Name 'opensearch_user' -Vault SecretStore -AsPlainText
    $base64AuthInfo = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f 'opensearch_user', $password)))
    $elasticUri = "https://opensearch_server:9200/syslog_*/_search?format=json"

$json = @"
{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          {
            "range": {
              "timestamp": {
                "gte": "now-1h"
              }
            }
          },
          {
            "term": {
              "mnemonic": "UPDOWN"
            }
          },
          {
            "term": {
              "facility": "LINK"
            }
          }
        ]
      }
    },
    "aggs": {
      "sources": {
        "terms": {
          "field": "source",
          "size": 10000
        },
        "aggs": {
          "interfaces": {
            "terms": {
              "field": "interface",
              "size": 10000
            },
            "aggs": {
              "latest_state_hit": {
                "top_hits": {
                  "size": 1,
                  "sort": [
                    {
                      "timestamp": {
                        "order": "desc"
                      }
                    }
                  ],
                  "_source": ["timestamp", "source", "interface", "state", "gl2_message_id", "gl2_remote_ip"]
                }
              }
            }
          }
        }
      }
    }
  }
  
"@
    $result = Invoke-RestMethod -Uri $elasticUri -Method POST -Body $json -ContentType application/json -Headers @{Authorization = ('Basic {0}' -f $base64AuthInfo) }
  
    $all = $result.aggregations.sources.buckets | ForEach-Object {
        $_.interfaces.buckets | ForEach-Object {
    $_.latest_state_hit.hits.hits._source
        }
    }

    if ($all) {
        $properties = @(
            'timestamp',
            'source',
            'interface',
            'state',
            'gl2_message_id',
            'gl2_remote_ip'
        )

        $inputobject = $all | Select-Object -Property $properties


        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'switches' -Table 'link_history' -OnConflict 'Set Excluded' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
}


Function Invoke-SwitchesScheduledFunction {
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
            Write-Output 'Get-SwitchInfoCSV'; Get-SwitchInfoCSV
            Write-Output 'Get-SwitchLinkHistory'; Get-SwitchLinkHistory
        }
        'Daily' {
            Write-Output 'Get-SwitchSNMPInformation'; Get-SwitchSNMPInformation
        }
    }

}