
function Get-IPv4 ( $Obj, $ObjInputAddress, $Prefix ) {
    $Obj | Add-Member -type NoteProperty -Name Type -Value 'IPv4'
        
    # Compute IP length
    [int] $IntIPLength = 32 - $Prefix
        
    $NumberOfIPs = ([System.Math]::Pow(2, $IntIPLength)) - 1
    $ArrBytesInputAddress = $ObjInputAddress.GetAddressBytes()
        
    [Array]::Reverse($ArrBytesInputAddress)
    $IpStart = ([System.Net.IPAddress]($ArrBytesInputAddress -join '.')).Address
    
    If (($IpStart.Gettype()).Name -ine 'double') {
        $IpStart = [Convert]::ToDouble($IpStart)
    }
    
    $IpStart = [System.Net.IPAddress] $IpStart
    $Obj | Add-Member -type NoteProperty -Name IpStart -Value $IpStart
    
    $ArrBytesIpStart = $IpStart.GetAddressBytes()
    [array]::Reverse($ArrBytesIpStart)
    $RangeStart = [system.bitconverter]::ToUInt32($ArrBytesIpStart, 0)
        
    
    $IpEnd = $RangeStart + $NumberOfIPs
    
    If (($IpEnd.Gettype()).Name -ine 'double') {
        $IpEnd = [Convert]::ToDouble($IpEnd)
    }
    
    $IpEnd = [System.Net.IPAddress] $IpEnd
    $Obj | Add-Member -type NoteProperty -Name IpEnd -Value $IpEnd
    
    $Obj | Add-Member -type NoteProperty -Name RangeStart -Value $RangeStart
        
    $ArrBytesIpEnd = $IpEnd.GetAddressBytes()
    [array]::Reverse($ArrBytesIpEnd)
    $Obj | Add-Member -type NoteProperty -Name RangeEnd -Value ([system.bitconverter]::ToUInt32($ArrBytesIpEnd, 0))
        
    Return $Obj
}


Function Get-MSGraphAPIHeaders {
    Connect-MSGraph
    $HeaderParams = @{ 'Authorization' = "$($MSGraphOauth.token_type) $($MSGraphOauth.access_token)" }
    return $HeaderParams
}


Function Get-O365Creds {
    $Username = "automation_account@$TenantName"
    $Password = Get-SecretFromVault -Vault $global:Vault -Name $Username
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $Password)
    return $creds
}

function Get-SecretFromVault {
    param (
        [string]$Vault,
        [string]$Name,
        [switch]$AsPlainText
    )

    <#
Quick little rundown on how to use the secret store:

MS Docs for reference: https://devblogs.microsoft.com/powershell/secretmanagement-and-secretstore-are-generally-available/

I believe you need to do all of this as the user the scripts will run under.


1. Setup

Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force
Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Import-Module Microsoft.PowerShell.SecretStore
Import-Module Microsoft.PowerShell.SecretManagement

Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

$credential = Get-Credential -UserName 'SecureStore'
$credential.Password | Export-Clixml -Path "$rootdir\Credentials\passwd.xml"
$password = Import-Clixml -Path  "$rootdir\Credentials\passwd.xml"

$storeConfiguration = @{
    Authentication  = 'Password'
    PasswordTimeout = 3600 # 1 hour
    Interaction     = 'None'
    Confirm         = $false
    Password        = $password
}

Set-SecretStoreConfiguration @storeConfiguration

3. Add Secrets!

Unlock-SecretStore -Password $password

$vault = 'SecretStore'
$Name = 'automation_account@your_company.com'

Set-Secret -Name $Name -Secret 'yourpasswordhere' -Vault $vault

4. Use this handy function for accessing the vault while playing nice with it, it doesn't like being queried 10x at once...

$Name = 'automation_account@your_company.com'
$secretpassword = Get-SecretFromVault -Vault $vault -Name $Name 

You can even make it give you the plaintext version as well if you need it
$plaintextpassword = Get-SecretFromVault -Vault $vault -Name $Name -AsPlainText

    #>

    $lock = [System.Threading.Mutex]::new($false, 'SecretVaultLock')
    [void]$lock.WaitOne()

    try {
        $securePasswordPath = "$rootdir\Credentials\passwd.xml"
        $password = Import-Clixml -Path $securePasswordPath
        Unlock-SecretStore -Password $password
        if ($AsPlainText) { $Secret = Get-Secret -Name $Name -Vault $Vault -AsPlainText }
        else { $Secret = Get-Secret -Name $Name -Vault $Vault }
        return $Secret
    }
    catch { $_.Exception }
    finally {
        $lock.ReleaseMutex()    
    }
}

Function Get-MSGraphDelegatedAuth {

    # Delegated auth is necessary for creating Planner tasks, you can't use application auth. You need to emulate a real user which will be used when creating Tasks.
    if ($Global:MSGraphDelegatedAuth.ExpiresOn.UtcDateTime -lt (Get-Date).AddMinutes(5).ToUniversalTime()) {
        $client = 'application id of your app registration'
        if (!(Test-Path "$rootdir\Binaries\microsoft.identity.client.4.58.1\lib\netstandard2.0\Microsoft.Identity.Client.dll")) {
            #binaries can be downloaded from https://www.nuget.org/api/v2/package/Microsoft.Identity.Client/4.58.1
            Write-Error 'Microsoft.Identity.Client.dll not found!'
        }
        try {
            Add-Type -Path "$rootdir\Binaries\microsoft.identity.client.4.58.1\lib\netstandard2.0\Microsoft.Identity.Client.dll" 
        }
        catch {}
        $publicClientApp = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($client).WithAuthority("https://login.microsoftonline.com/$tenantid").Build()
        $Username = "automation_account@$TenantName"
        $Password = Get-SecretFromVault -Vault $global:vault -Name "automation_account@$TenantName"
        $Scopes = New-Object System.Collections.Generic.List[string]
        $Scopes.Add('https://graph.microsoft.com/.default')
        $global:MSGraphDelegatedAuth = $publicClientApp.AcquireTokenByUsernamePassword($Scopes, $username, $Password).ExecuteAsync().Result
        return $global:MSGraphDelegatedAuth
    }
    else {
        return $global:MSGraphDelegatedAuth
    }

}

Function Get-MSGraphDelegatedAuthHeader {
    if ($Global:MSGraphDelegatedAuth.ExpiresOn.UtcDateTime -lt (Get-Date).AddMinutes(5).ToUniversalTime()) {
        $authenticationResult = Get-MSGraphDelegatedAuth
        $Header = @{ 'Authorization' = "$($authenticationResult.TokenType) $($authenticationResult.AccessToken)" }
    }
    else {
        $Header = @{ 'Authorization' = "$($Global:MSGraphDelegatedAuth.TokenType) $($Global:MSGraphDelegatedAuth.AccessToken)" }
    }
    return $Header
}




function Get-Chunks ([object[]]$InputObject, [int]$SplitSize = 20) {
    $length = $InputObject.Length
    for ($Index = 0; $Index -lt $length; $Index += $SplitSize = 20) {
        , ($InputObject[$index..($index + $splitSize - 1)])
    }
}

function Get-CustomChunks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [object[]]
        $InputObject, 
        [Parameter(mandatory = $true)]
        [int]$SplitSize
    )
    $length = $InputObject.Length
    for ($Index = 0; $Index -lt $length; $Index += $SplitSize) {
        , ($InputObject[$index..($index + $splitSize - 1)])
    }
}



Function Get-MSGraphAPIData {
    param (
        [parameter(Mandatory = $true)]
        $ClientID,
   
        [parameter(Mandatory = $true)]
        $ClientSecret,
   
        [parameter(Mandatory = $true)]
        $TenantName,
   
        [parameter(Mandatory = $true)]
        $Url
    )
   
   
    # Graph API URLs.
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
    try {
        $Result = (Invoke-RestMethod -Headers $HeaderParams -Uri $Url -Method Get)
        # Return result.
        
    }
    catch { $_.exception }
    return $Result
}

Function Connect-MSGraph {
  
    $LoginUrl = 'https://login.microsoft.com'
    $ResourceUrl = 'https://graph.microsoft.com'
    $Body = @{ grant_type = 'client_credentials'; resource = $ResourceUrl; client_id = $ClientID; client_secret = $ClientSecret }
    
    if (!$MSGraphOauth -or ([DateTimeOffset]::Now.ToUniversalTime().AddMinutes(-5).ToUnixTimeSeconds() -gt $MSGraphOauth.expires_on )) {
        $global:MSGraphOauth = Invoke-RestMethod -Method Post -Uri $LoginUrl/$TenantName/oauth2/token?api-version=1.0 -Body $Body
        Connect-MgGraph -AccessToken ($MSGraphOauth.access_token | ConvertTo-SecureString -AsPlainText) | Out-Null
    } 
    else {
        Connect-MgGraph -AccessToken ($MSGraphOauth.access_token | ConvertTo-SecureString -AsPlainText) -ErrorAction SilentlyContinue -ErrorVariable MSGraphOauthError | Out-Null
        if ($MSGraphOauthError) {
            $global:MSGraphOauth = Invoke-RestMethod -Method Post -Uri $LoginUrl/$TenantName/oauth2/token?api-version=1.0 -Body $Body
        }
        
    }
    
}

function Get-TotalDaysInMonth {
    param (
        [Parameter(Position = 0)]
        [DateTime]$Date = (Get-Date)
    )

    $firstDayOfMonth = (Get-Date -Day 1 -Month $Date.Month -Year $Date.Year)
    $firstDayOfNextMonth = (Get-Date -Day 1 -Month ($Date.Month + 1) -Year $Date.Year)
    $totalDaysInMonth = ($firstDayOfNextMonth - $firstDayOfMonth).Days

    return $totalDaysInMonth
}

function Get-DaysLeftInMonth {
    param (
        [Parameter(Position = 0)]
        [DateTime]$Date = (Get-Date)
    )

    $lastDayOfMonth = (Get-Date -Day 1 -Month ($Date.Month + 1) -Year $Date.Year).AddDays(-1)
    $daysLeft = ($lastDayOfMonth - $Date).Days + 1

    return $daysLeft
}



Function Get-VariableSizes {

    # Use this for troubleshooting high memory usage caused by big variables
    function Get-VariableSize ($var) {
        $ms = New-Object System.IO.MemoryStream
        $formatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
        $formatter.Serialize($ms, $var)
        $ms.Length
    }
    
    # Get all currently loaded variables
    $variables = Get-Variable
    
    $skip = @(
        'check',
        'variables',
        'varsizes',
        '__LastHistoryId',
        '__VSCodeOriginalPrompt',
        '?',
        '^',
        '$',
        'args',
        'ConfirmPreference',
        'DebugPreference',
        'EnabledExperimentalFeatures',
        'Error',
        'ErrorActionPreference',
        'ErrorView',
        'ExecutionContext',
        'false',
        'FormatEnumerationLimit',
        'HOME',
        'Host',
        'InformationPreference',
        'input',
        'IsCoreCLR',
        'IsLinux',
        'IsMacOS',
        'IsWindows',
        'MaximumHistoryCount',
        'MyInvocation',
        'NestedPromptLevel',
        'null',
        'OutputEncoding',
        'PID',
        'PROFILE',
        'ProgressPreference',
        'PSBoundParameters',
        'PSCommandPath',
        'PSCulture',
        'PSDefaultParameterValues',
        'PSEdition',
        'psEditor',
        'PSEmailServer',
        'PSHOME',
        'PSNativeCommandArgumentPassing',
        'PSScriptRoot',
        'PSSessionApplicationName',
        'PSSessionConfigurationName',
        'PSSessionOption',
        'PSStyle',
        'PSUICulture',
        'PSVersionTable',
        'PWD',
        'ShellId',
        'StackTrace',
        'true',
        'VerbosePreference',
        'WarningPreference',
        'WhatIfPreference'
    )
    
    $check = $variables | Where-Object { $_.Name -notin $skip }
    
    $varsizes = foreach ($var in $check) {
        # Exclude certain system variables that can't be serialized
        if ($var.Name -notin $skip) {
            try {
                $size = Get-VariableSize $var.Value
            }
            catch {
                $size = $null
            }
            [PSCustomObject]@{
                Name = $var.Name
                Size = $size
            }
        }
    }
    
    $varsizes | Sort-Object -Property Size
    
}
$global:mycompany = 'mycompanyname'
$global:domain_controller = 'server'
$global:ad_domain = 'MYDOMAIN' #caps for case sensitive postgres queries
$global:commvault_commserve = 'server'
$global:sccm_site = 'ABC'
$global:sccm_server = 'sccmserver'
$global:dns_suffix = '.mycompany.com'
$global:tenantId = 'your tenant guid here'
$global:ClientID = 'your client id here' 
$global:ClientSecret = 'your client secret here' 
$global:TenantName = 'your tenant name' 
[regex]$global:ipv4grok = '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])'
$global:grafanatableheaders = @'
<style>
body {
    height: 100%;
    width: 100%;
    position: absolute;
    color: rgb(204, 204, 220);
    background-color: rgb(17, 18, 23);
    margin: 0px 0px 0.45em;
    /*line-height: 1.57143;*/
    font-weight: 400;
    letter-spacing: 0.01071em;
    font-family: Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
}
table {
    border: 1px solid #ccccdc12;
    border-radius: 3px;
    box-shadow: none;
    display: flex;
    flex: 1 1 0;
    flex-direction: column;
    height: 100%;
    position: relative;
    width: 100%;
}
th,
tr {
    padding: 6px;
    overflow: hidden;
    white-space: nowrap;
    color: rgb(110, 159, 255);
    border-right: 1px solid rgba(204, 204, 220, 0.07);
    height: 34px;
    overflow: hidden auto;
    background: rgb(34, 37, 43);
    /*border: 1px solid #ccccdc12;
    border-radius: 3px;*/
}
td {
  padding: 15px;
  color: #ccccdc;
  border-right: 1px solid rgba(204, 204, 220, 0.07);
}
tbody td {
  background-color: #181b1f;
}
</style>
'@
$global:Vault = 'SecretStore'