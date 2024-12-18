$sqlkeywords = @(
    'ALL',
    'ANALYSE',
    'ANALYZE',
    'AND',
    'ANY',
    'ARRAY',
    'AS',
    'ASC',
    'ASYMMETRIC',
    'BOTH',
    'CASE',
    'CAST',
    'CHECK',
    'COLLATE',
    'COLUMN',
    'CONSTRAINT',
    'CREATE',
    'CURRENT_DATE',
    'CURRENT_ROLE',
    'CURRENT_TIME',
    'CURRENT_TIMESTAMP',
    'CURRENT_USER',
    'DEFAULT',
    'DEFERRABLE',
    'DESC',
    'DISTINCT',
    'DO',
    'ELSE',
    'END',
    'EXCEPT',
    'FALSE',
    'FOR',
    'FOREIGN',
    'FROM',
    'GRANT',
    'GROUP',
    'HAVING',
    'IN',
    'INITIALLY',
    'INTERSECT',
    'INTO',
    'LEADING',
    'LIMIT',
    'LOCALTIME',
    'LOCALTIMESTAMP',
    'NEW',
    'NOT',
    'NULL',
    'OFF',
    'OFFSET',
    'OLD',
    'ON',
    'ONLY',
    'OR',
    'ORDER',
    'PLACING',
    'PRIMARY',
    'REFERENCES',
    'SELECT',
    'SESSION_USER',
    'SOME',
    'SYMMETRIC',
    'TABLE',
    'THEN',
    'TO',
    'TRAILING',
    'TRUE',
    'UNION',
    'UNIQUE',
    'USER',
    'USING',
    'WHEN',
    'WHERE'
)

Function Test-PGODBCDriver {
    <#
    .SYNOPSIS
        Checks to see if the PostgreSQL ODBC Driver is installed
    .DESCRIPTION
        Generates a terminating error if the PostgreSQL ODBC Driver can not be found. Only has to run this check once per session.
    #>
    
    if ($PostgreSQLODBCDriverPresent -ne $true) {

        if ($null -eq (Get-OdbcDriver -Name *PostgreSQL*)) {
            throw 'PostgreSQL ODBC Driver not found, install latest release from https://www.postgresql.org/ftp/odbc/releases/'
        }
        else {
            $global:PostgreSQLODBCDriverPresent = $true
        }
    }
}



Function Get-PGSQLTableDefinitions {
    param(
        [switch]
        $Force
    )
    <#
    .SYNOPSIS
        Retrieves all column information from DB
    .DESCRIPTION
        Stores all table schemas, table names, column names, and column data types for quick retrieval. Module must be forcibly imported to update the table definitions variable.
    .NOTES
        This function exists to reduce the amount of queries done against the DB. By storing the table definitions in a variable, we can reference this in memory instead of querying the DB before each insert.
    #>
    if ($null -eq $tabledefinitions[0] -or $Force) {

        $query = @'
    SELECT table_schema,table_name,column_name,data_type,is_nullable
    FROM information_schema.columns
    where table_schema not like '%timescaledb_%'
    and table_schema not in ('information_schema','pg_catalog')
'@
        [System.Data.Odbc.OdbcCommand]$pgsqlcmd = New-Object System.Data.Odbc.OdbcCommand($query, $PgSqlConnection)
        [System.Data.Odbc.odbcDataAdapter]$pgsqlda = New-Object system.Data.odbc.odbcDataAdapter($pgsqlcmd)    
        $pgsqlds = [System.Data.DataSet]::new()
        $pgsqlda.Fill($pgsqlds) | Out-Null

        $global:tabledefinitions = $pgsqlds.Tables.ForEach{ $_ }

        $pgsqlcmd.Dispose()
        $pgsqlda.Dispose()
        $pgsqlds.Dispose()
    
    }
}

Function Connect-PGSQLServer {

    begin {
        Test-PGODBCDriver
    }
    process {
  
        try {
            if ($null -eq $PgSqlConnection) {
                $pgsqlUser = 'postgres_user'
                $pgsqlPass = Get-SecretFromVault -Vault $global:Vault -Name $pgsqlUser
                $pgsqldbName = 'dbname'
                $pgsqlServer = 'pgsqlserver'
                $port = 5432
                $PgSqlConnection = New-Object System.Data.Odbc.OdbcConnection
                $PgSqlConnection.ConnectionString = "Driver={PostgreSQL Unicode(x64)};Server=$pgsqlServer;Port=$Port;Database=$pgsqldbName;Uid=$pgsqlUser;Pwd=$pgsqlPass;Pooling=true;"
                $PgSqlConnection.ConnectionTimeout = 60
                $PgSqlConnection.Open()
                $global:PgSqlConnection = $PgSqlConnection
            }
            elseif ( $PgSqlConnection.State -eq 'Closed') {
                $PgSqlConnection.Open()
            }
            
            Get-PGSQLTableDefinitions
            
        }
        catch {
            $ip = (Get-NetIPAddress | Where-Object { $_.InterfaceIndex -in ((Get-NetAdapter | Where-Object { $_.status -eq 'Up' }).ifindex) -and $_.AddressFamily -eq 'IPv4' }).IPAddress
            Write-Error "Postgresql Connection Failed. If necessary, make sure your Postgresql server is listening on non-local ports and your pg_hba.conf has been modified accordingly. You may need an entry such as 'host all all $ip/32 trust'"
            throw $_.exception
        }
        finally {
        
        }
    }
}

Function Disconnect-PGSQLServer {
    
    try {
        if ($PgSqlConnection.State -eq 'Open') {
            $PgSqlConnection.Close()
        }
    }
    catch {
        $_.exception.message
    }

}

Function Invoke-PGSQLSelect {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Query
    )

    process {
        Connect-PGSQLServer
        try {
            [System.Data.Odbc.OdbcCommand]$pgsqlcmd = New-Object System.Data.Odbc.OdbcCommand($query, $PgSqlConnection)
            [System.Data.Odbc.odbcDataAdapter]$pgsqlda = New-Object system.Data.odbc.odbcDataAdapter($pgsqlcmd)    
            $pgsqlds = [System.Data.DataSet]::new()
            $pgsqlda.Fill($pgsqlds) | Out-Null
            $pgsqldt = $pgsqlds.Tables.ForEach{ $_ }
            return $pgsqldt
        }
        catch {
            # uncomment the line below and comment out the throw if you don't want select statements to kill the whole script
            #Write-Error $_
            throw $_.exception
        }
    }
    end {
        $pgsqlcmd.Dispose()
        $pgsqlda.Dispose()
        $pgsqlds.Dispose()
    }
   
}


Function Set-PGSQLInsert {
    <#
    .SYNOPSIS
        Builds a Postgresql insert query statement
    .DESCRIPTION
        Used by the "Invoke-PGSQLInsert" function, this function builds the entire insert query statement and creates a single large insert statement instead of multiple single inserts.
    .NOTES
        This function has multiple functionalities:
            - Queries the DB to try and best-match the columns in your $InputObject variable. This allows you to not specify object properties while only inserting properties(columns) that already exist in the table.
            - Normalizes property names (removes certain special characters and changes the case to lower)
            - Identifies primary keys for use with "ON CONFLICT" and "DO UPDATE SET" (for updating data without truncating the table)
            - Automatically replaces single quotes with double single quotes
            - Handles null values (and weird stuff like [dbnull]) by always converting all values to a string with [string]$member.value 
            - Automatically wraps Postgresql key words with double quotes
            - Automatically wraps schema names with double quotes in case of upper case characters
    .EXAMPLE
        Set-PGSQLInsert -InputObject $InputObject -OnConflict 'Set Excluded' -Schema activedirectory -Table computers
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Do Nothing', 'Set Excluded', 'null')]
        [string]
        $OnConflict,
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
    try {
        $schema = $Schema
        $table = $table
        $columns = @()
        $values = $null
        $definitions = @()
        $pgColumns = @()
        $insertstatement = $null
        $Columns = ($InputObject | Get-Member).Where({ $_.membertype -in ('Property', 'NoteProperty') }) | Select-Object name,
        @{name = 'Property'; expression = { $_.name.trim().tolower() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } }, 
        @{name = 'DataType'; expression = { $_.definition.split(' ')[0] } } -Unique | Sort-Object -Property name


        #$definitions = Invoke-PGSQLSelect -Query "SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema = '$schema' and table_name = '$table'"
        $definitions = $tabledefinitions | Where-Object { $_.table_schema -ceq $schema -and $_.table_name -ceq $table } | Select-Object column_name, data_type, is_nullable
        if (!$definitions) {
            Write-Error "$schema.$table - Does not exist"
            break
        }

        $pgColumns = $columns.Where({ $_.property -in $definitions.column_name })
        $comparecolumns = ($inputobject[0].psobject.properties).name.trim().tolower() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_'
        $insertcolumns = @()
        $selcolumns = @()
        foreach ($column in $comparecolumns) {
            if ($column -in $pgColumns.property) {
                $column = $pgColumns.where({ $_.Property -eq $column })
                ($column.Property -in $sqlkeywords) ?  ($insertcolumns += '"' + "$($column.Property)" + '"') : ($insertcolumns += $column.Property) | Out-Null
                $selcolumns += $column.name
            }
        }

        if (-not (Compare-Object @($comparecolumns) @($pgcolumns.name)) ) {
        }
        else {
            $InputObject = $InputObject | Select-Object -Property $selcolumns
        }

        $pgcolumns_string = [System.String]::Join(', ', $insertcolumns)
        $pkeys = ($definitions.Where({ [string]$_.is_nullable -eq 'NO' })).column_name
        if ($null -eq $pkeys) {
            Write-Error 'Primary Keys have not been defined'
            break
        }
        $pkeys_string = [System.String]::Join(',', $pkeys)
        $excluded = ($definitions.Where({ [string]$_.is_nullable -eq 'YES' })).column_name
            
        $values = [System.String]::Join(',', (& { foreach ($property in $InputObject) {
                        $membervalues = foreach ($member in $($property.psobject.properties)) {
                            $membervalue = [string]$member.value
                        ($membervalue) ?  ("'" + $membervalue.Replace("'", "''") + "'") : ('Null')
                        } 
                        '(' + [System.String]::Join(',', $membervalues) + ')'
                    } }))


        switch ($onconflict) {
            'Set Excluded' { 
                if ($excluded) {
                    $excludedcolumns = foreach ($exc in $excluded) {
                        if ($exc -in $sqlkeywords) { $exc = "`"$exc`"" }
                        "$exc=EXCLUDED.$exc"
                    }
                    $excludedcolumns = [System.String]::Join(',', $excludedcolumns)
                    $conflictstatement = "ON CONFLICT ($pkeys_string) DO UPDATE SET $excludedcolumns"
                }
                else {
                    $conflictstatement = 'ON CONFLICT DO NOTHING'
                }
                break
            }
            'Do Nothing' {
                $conflictstatement = 'ON CONFLICT DO NOTHING'
                break
            }
            'null' {
                $conflictstatement = $null 
                break
            }
            Default { $conflictstatement = $null }
        }

    ($schema -cmatch '[A-Z]') ?  ($insertinto = "`"$($schema)`".$table ($pgcolumns_string)") : ($insertinto = "$($schema).$table ($pgcolumns_string)") | Out-Null

        $insertstatement = @"
    INSERT INTO $insertinto
    VALUES $values
    $conflictstatement;
"@
    
        return $insertstatement
    }
    catch {
        $_.Exception
    }
    finally {
        $values = $null
        $insertstatement = $null
    }
}
Function Invoke-PGSQLTruncate {
    <#
    .SYNOPSIS
        Truncates a Postgresql table
    .DESCRIPTION
        Executes a truncate table query on the specified table
    .EXAMPLE
        Invoke-PGSQLTruncate -Schema 'activedirectory' -Table 'computers'
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
 
    $truncatestatement = Set-PGSQLTruncate -Schema $Schema -Table $Table
    try {
        [System.Data.Odbc.OdbcCommand]$truncatecmd = New-Object System.Data.Odbc.OdbcCommand($truncatestatement, $PgSqlConnection)
        [void]$truncatecmd.ExecuteNonQuery()
    }
    catch {
        Write-Error $_.Exception
    }
    finally {
        $truncatecmd.Dispose()
    }

    
}

Function Set-PGSQLTruncate {
    <#
    .SYNOPSIS
        Builds a Postgresql truncate query statement
    .DESCRIPTION
        Builds a Postgresql truncate query statement using the specified schema and table
    .EXAMPLE
        Set-PGSQLTruncate -Schema 'activedirectory' -Table 'computers'
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table
    )
 
    if ($schema -cmatch '[A-Z]') { $truncatestatement = "truncate table `"$($schema)`".$table;" }
    else { $truncatestatement = "truncate table $($schema).$table;" }
    
    return $truncatestatement
    
}
Function Invoke-PGSQLInsert {
    <#
    .SYNOPSIS
        A short one-line action-based description, e.g. 'Tests if a function is valid'
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        # Complete Copy: You want to store an up-to-date copy of your Active Directory computers and want a clean/fresh set of data, truncate the existing table

        Invoke-PGSQLInsert -InputObject $InputObject -OnConflict 'Do Nothing' -Schema 'activedirectory' -Table 'computers' -Truncate $true
    .EXAMPLE
        # Time Series Data:  You want to track metrics over time and don't want to truncate the table. By setting -OnConflict to 'Set Excluded', we can update the data in the 'Value' column (assuming the Date and Metric columns are set as primary keys)
        $InputObject = [PSCustomObject]@{
                        Date = (Get-date).tostring('yyyy-MM-dd')
                        'Metric' = 'Total Machines'
                        'Value' = 12345
                        }

        Invoke-PGSQLInsert -InputObject $InputObject -OnConflict 'Set Excluded' -Schema 'activedirectory' -Table 'total_machines_history' -Truncate $false
    #>
    
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Do Nothing', 'Set Excluded', 'null')]
        [string]
        $OnConflict,
        [Parameter(Mandatory = $true)]
        [string]
        $Schema,
        [Parameter(Mandatory = $true)]
        [string]
        $Table,
        [Parameter(Mandatory = $true)]
        [ValidateSet($true, $false)]
        [bool]
        $Truncate
    )
    process {
        $PgInsertQuery = $null
        if ($truncate -eq $true) {
            $PgInsertQuery = Set-PGSQLTruncate -Schema $Schema -Table $Table
        }

        $PgInsertQuery += Set-PGSQLInsert -InputObject $InputObject -OnConflict $OnConflict -Schema $Schema -Table $Table


        try {
            [System.Data.Odbc.odbcDataAdapter]$da = New-Object system.Data.odbc.odbcDataAdapter
            $da.InsertCommand = New-Object System.Data.Odbc.OdbcCommand($PgInsertQuery, $PgSqlConnection)
            $da.InsertCommand.Prepare()
            [void]$da.InsertCommand.ExecuteNonQuery()

        }
        catch {
            Write-Error $_
        }
        finally {
            $da.Dispose()
        }

    }
    
}

Function Add-PGSQLTable {

    <#
    .SYNOPSIS
        Creates a Postgresql table using a powershell object
    .DESCRIPTION
        This function will create a postgresql table based on the input object. A GUI will be displayed where you can choose schema name, table name, primary keys, and columns/data types
    .NOTES
        This function replaces certain special characters in property names with "-replace '(\(|\)|\%)', '' -replace '( |/|-)', '_'" and also converts all column names to lower case

        This function assumes you have a group called "readonly" that you use to give select permissions

    CREATE ROLE readonly WITH
	NOLOGIN
	NOSUPERUSER
	NOCREATEDB
	NOCREATEROLE
	INHERIT
	NOREPLICATION
	NOBYPASSRLS
	CONNECTION LIMIT -1;

    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject
    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject -GrantReadOnly -ReadOnlyGroup 'read_only_users'
    .EXAMPLE
        Add-PGSQLTable -InputObject $inputobject -Table 'Computers' -Schema 'ActiveDirectory' -PrimaryKeys @('ObjectGUID')
    #>
    
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [psobject]
        $InputObject,
        # Shows PowerShell object in Out-Gridview.
        [Parameter(HelpMessage = 'Shows PowerShell object in Out-Gridview.')]
        [switch]
        $GridView,
        # Grant permission to specified ReadOnly group.
        [Parameter(
            Position = 1,
            ParameterSetName = 'ReadOnly',
            Mandatory = $false,
            HelpMessage = 'Grant permission to specified ReadOnly group.')]
        [switch]
        $GrantReadOnly,
        # ReadOnly group to grant permissions to.
        [Parameter(
            Position = 2,
            ParameterSetName = 'ReadOnly',
            Mandatory = $false,
            HelpMessage = 'ReadOnly group to grant permissions to.')
        ]
        [string]
        $ReadOnlyGroup,
        [string]
        $Table,
        [string]
        $Schema,
        [array]
        $PrimaryKeys
    )
    
    begin {
        Connect-PGSQLServer
        if (-not $PSBoundParameters.ContainsKey('GrantReadOnly')) {
            $GrantReadOnly = $false
        }

        if (-not $PSBoundParameters.ContainsKey('GridView')) {
            $GridView = $false
        }
    }
    process {
        if ($GrantReadOnly -eq $true) {
            if ($ReadOnlyGroup -eq '') {
                throw 'ReadOnlyGroup value missing'
            }
            elseif ($ReadOnlyGroup -ne '') {
                $readonlygroup_exists = Invoke-PGSqlQuery -Type Select -Query "select * from pg_group where groname = '$ReadOnlyGroup'"
                if ($null -eq $readonlygroup_exists) {
                    $errormessage = @"

Postgresql Group "$ReadOnlyGroup" is missing and needs to be created.
Create statement:

    CREATE ROLE readonly WITH
	NOLOGIN
	NOSUPERUSER
	NOCREATEDB
	NOCREATEROLE
	INHERIT
	NOREPLICATION
	NOBYPASSRLS
	CONNECTION LIMIT -1;

"@
                    Write-Error -Message $errormessage
                    break
                }
            }
        }

        $definitions = $InputObject[0] | Get-Member | Where-Object { $_.membertype -in ('Property', 'NoteProperty') } | Select-Object @{name = 'Property'; expression = { $_.name.trim() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } }, @{name = 'DataType'; expression = { $_.definition.split(' ')[0] } }

        $types = @(
            'int',                                        
            'string',                                     
            'bool',
            'System.Boolean',                                     
            'System.Management.Automation.PSCustomObject',
            'object',                                     
            'Object[]',
            'System.Object[]',                                   
            'guid',                                       
            'datetime',                                   
            'decimal',                                    
            'long',                                       
            'single',                                     
            'double',
            'System.String',
            'System.Int32',
            'System.Int64',
            'System.DateTime',
            'ipaddress',
            'uint32',
            'byte',
            'System.Net.IPAddress',
            'System.Double',
            'short',
            'string[]'                                 
        )
        $missingtypes = @()

        foreach ($field in $definitions) {
            if ($field.DataType -notin $types) {
                $missingtypes += $field
            }
        }
        if ($missingtypes) {
            Write-Host -ForegroundColor Red 'Your data contains unsupported types, they may need to be added to $types'
            Write-Host $missingtypes
            break
        }
  
        if ($GridView -eq $true) {
            $data | Out-GridView -Wait
            $msg = 'Do you want to continue? [Y/N]'
            $response = Read-Host -Prompt $msg
            if ($response -eq 'n') { break }
        }

        $tabledata = Set-PGTableProperties -object $InputObject -TableName $Table -SchemaName $Schema -PrimaryKeys $PrimaryKeys
        $fields = $tabledata.Fields
        $pkey = $tabledata.PKey
        $tablename = $tabledata.TableName
        $schemaname = $tabledata.SchemaName

        if ($CancelButtonClicked -eq $true) {
            throw
        }
        if ($pkey.count -lt 1 -or $null -eq $pkey) {
            Write-Host "WARNING: You didn't select any primary keys" -ForegroundColor Yellow
        }

     
        $keywordspattern = "($($($sqlkeywords -replace '^.{0}','^' -replace '.{0}$','$') -join '|'))"

        $pght = @{}
        $pgfields = $fields | Select-Object @{name = 'Name'; expression = { $_.Name.ToLower() -replace $keywordspattern, '"$1"' } }, Value
        $pgfields | ForEach-Object { $pght[$_.Name] = $_.value }

        $pgdefinitions = $definitions | Select-Object @{name = 'property'; expression = { $_.Property.ToLower() -replace $keywordspattern, '"$1"' } }, datatype
        $pgdefinitions = $pgdefinitions | Select-Object property, datatype, @{name = 'PGType'; expression = { $pght["$($_.Property)"] } }
        $pgcolumns = $pgdefinitions | Where-Object { $_.Property -in $pgfields.name }
        $pkey = $pkey.ToLower() -replace $keywordspattern, '"$1"'


        $pkey_value = $pkey -join ','
        $pkey_name = $tablename + '_pkey'

        $columns = foreach ($column in $pgcolumns) {
            ($column.property -in $pkey) ?  "$($column.Property) $($column.PgType) NOT NULL," : "$($column.Property) $($column.PgType),"
        }

         
        $createschema = ($schemaname -cmatch '[A-Z]') ?  "`"$schemaname`"" : $schemaname
   
        
        $createtablestatement = @"
CREATE TABLE $createschema.$tablename
(
$columns
CONSTRAINT $pkey_name PRIMARY KEY ($($pkey_value))
)
"@


        $tableexists = Invoke-PGSQLSelect -Query "SELECT * from information_schema.tables WHERE table_schema = '$schemaname' and table_name = '$tablename'" 

        if ($tableexists) {
            Write-Host "$createschema.$tablename - Already Exists" -ForegroundColor Red
            break
        }



        Invoke-PGSQLSelect -Query $createtablestatement
        Write-Host -Object $createtablestatement -ForegroundColor Blue
        
        $tablecreated = Invoke-PGSQLSelect -Query "SELECT * from information_schema.tables WHERE table_schema = '$schemaname' and table_name = '$tablename'" 
        if ($tablecreated) {
            Write-Host "$createschema.$tablename - Created Successfully" -ForegroundColor Green
        
            if ($GrantReadOnly) {
                Invoke-PGSQLSelect -Query "grant select on $createschema.$tablename to $ReadOnlyGroup;"
                Write-Host "$createschema.$tablename - Granted Select to `"$ReadOnlyGroup`"" -ForegroundColor Green
            }
        }
 

    }
    end {
        Get-PGSQLTableDefinitions -Force
        Disconnect-PGSQLServer
    }
    
}


Function Set-PGTableProperties {

    <#
.SYNOPSIS
    Returns Postgresql table properties
.DESCRIPTION
    Creates a GUI to select a table name, schema name, primary keys, and columns
.NOTES
    Accepts -TableName, -SchemaName, and -Pkeys parameters
.EXAMPLE
    Set-PGTableProperties -object $InputObject
.EXAMPLE
    Set-PGTableProperties -object $InputObject -TableName $Table -SchemaName $Schema -PKeys $Pkeys
#>



    param (
        [Parameter(Mandatory = $true)]
        $Object,
        [string]
        $TableName,
        [string]
        $SchemaName,
        [array]
        $PrimaryKeys
    )
    $Global:CancelButtonClicked = $false

    $properties = $object[0] | Get-Member | Where-Object { $_.membertype -in ('Property', 'NoteProperty') } | Select-Object @{name = 'Property'; expression = { $_.name.trim() -replace '(\(|\)|\%)', '' -replace '( |/|-)', '_' } }, @{name = 'DataType'; expression = { $_.definition.split(' ')[0] } }

    if ($null -eq $properties) { Write-Host "Couldn't find any Property/NoteProperty data"; break }
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing') 
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') 

    #This creates the form and sets its size and position
    $global:objForm = New-Object System.Windows.Forms.Form 
    $objForm.Text = 'Postgres Table Builder'
    $objForm.Size = New-Object System.Drawing.Size(1000, 800) 
    #$objForm.AutoSize = $true
    $objForm.FormBorderStyle = 'sizable'
    $objForm.StartPosition = 'CenterScreen'

    $objForm.KeyPreview = $True
    $objForm.Add_KeyDown( { if ($_.KeyCode -eq 'Enter') 
            { $objTextBox1.Text; $objTextBox2.Text; $listbox1.selecteditems; $listbox2.checkeditems; $objForm.Close() } })
    $objForm.Add_KeyDown( { if ($_.KeyCode -eq 'Escape') 
            { $objForm.Close() } })

    #This creates a label for the TextBox1
    $objLabel1 = New-Object System.Windows.Forms.Label
    $objLabel1.Location = New-Object System.Drawing.Size(10, 20) 
    $objLabel1.Size = New-Object System.Drawing.Size(280, 20) 
    $objLabel1.Text = 'Enter the table name'
    $objLabel1.TabIndex = 0 
    $objForm.Controls.Add($objLabel1) 

    #This creates the TextBox1
    $objTextBox1 = New-Object System.Windows.Forms.TextBox 
    $objTextBox1.Location = New-Object System.Drawing.Size(10, 40) 
    $objTextBox1.Size = New-Object System.Drawing.Size(260, 20)
    $objTextBox1.TabIndex = 0 
    if ($PSBoundParameters['TableName']) { $objTextBox1.Text = $TableName }
    $objForm.Controls.Add($objTextBox1)
    
    
    

    #This creates a label for the TextBox2
    $objLabel2 = New-Object System.Windows.Forms.Label
    $objLabel2.Anchor = 'top,right'
    $objLabel2.Location = New-Object System.Drawing.Size(600, 20) 
    $objLabel2.Size = New-Object System.Drawing.Size(280, 20) 
    $objLabel2.Text = 'Select the schema name'
    $objLabel2.TabIndex = 0 
    $objForm.Controls.Add($objLabel2) 

    #This creates the TextBox2
    $objTextBox2 = New-Object System.Windows.Forms.ComboBox 
    $objTextBox2.DropDownStyle = 'DropDown'
    $objTextBox2.anchor = 'top,right'
    $objTextBox2.Location = New-Object System.Drawing.Size(600, 40) 
    $objTextBox2.Size = New-Object System.Drawing.Size(260, 20)
    #$objTextBox2.Height = 80
    $objTextBox2.TabIndex = 0 
    $objForm.Controls.Add($objTextBox2)
    $schemas = (Invoke-PGSQLSelect -Query "SELECT distinct schema_name from information_schema.schemata where schema_name not like '%timescaledb_%'").schema_name | Sort-Object
    Foreach ($schema_name in $schemas) {
        [void] $objTextBox2.Items.Add($schema_name)
    }
    if ($PSBoundParameters['SchemaName']) { $objTextBox2.SelectedItem = $SchemaName }

    #This creates a label for the ListBox1
    $listbox1label = New-Object System.Windows.Forms.Label
    $listbox1label.Location = New-Object System.Drawing.Size(10, 75) 
    $listbox1label.Size = New-Object System.Drawing.Size(280, 20) 
    $listbox1label.Text = 'Select Postgres Fields'
    $listbox1label.TabIndex = 0 
    $objForm.Controls.Add($listbox1label) 





    #This creates a label for the ListBox2
    $listbox2label = New-Object System.Windows.Forms.Label
    $listbox2label.Anchor = 'top,right'
    $listbox2label.Location = New-Object System.Drawing.Size(600, 75) 
    $listbox2label.Size = New-Object System.Drawing.Size(280, 20) 
    $listbox2label.Text = 'Select Primary Keys'
    $listbox2label.TabIndex = 0 
    $objForm.Controls.Add($listbox2label) 
    #This creates the ListBox2
    $listbox2 = New-Object System.Windows.Forms.CheckedListBox
    $listbox2.Anchor = 'top,right'
    $listbox2.Location = New-Object System.Drawing.Size(600, 100) 
    $listbox2.Size = New-Object System.Drawing.Size(325, 550)
    $listbox2.TabIndex = 11
    $listbox2.CheckOnClick = $true
    $objForm.Controls.Add($listbox2)
 
    Foreach ($property in $properties.property) {
        if ($property -in $PrimaryKeys) {
            [void] $listbox2.Items.Add($property, [System.Windows.Forms.CheckState]::Checked)
        }
        else { 
            [void] $listbox2.Items.Add($property) 
        }
    }
       
 
    #This creates the Ok button and sets the event
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Anchor = 'bottom'
    $OKButton.Location = New-Object System.Drawing.Size(100, 700)
    $OKButton.Size = New-Object System.Drawing.Size(75, 23)
    $OKButton.Text = 'OK'
    $OKButton.Add_Click( { $objTextBox1.Text; $objTextBox2.Text; $dgv.selectedrows; $listbox2.checkeditems; $objForm.Close() })
    $OKButton.TabIndex = 0
    $objForm.Controls.Add($OKButton)

    #This creates the Cancel button and sets the event
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Anchor = 'bottom'
    $CancelButton.Location = New-Object System.Drawing.Size(200, 700)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.Add_Click( { $global:CancelButtonClicked = $true; $objForm.Close() })
    $CancelButton.TabIndex = 0
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel 
    $objForm.Controls.Add($CancelButton)
    $objForm.Add_Shown( { $objForm.Activate() })
    $objForm.CancelButton = $CancelButton

    $DataTable1 = New-Object System.Data.DataTable
    [void] $DataTable1.Columns.Add('Property')
    [void] $DataTable1.Columns.Add('DataType')


    Foreach ($property in $properties) {
        [void] $DataTable1.Rows.Add($property.Property, $property.DataType)
    }  


    $convert = @{
        'int'                                         = 'integer'
        'string'                                      = 'text'
        'bool'                                        = 'text'
        'System.Boolean'                              = 'text'
        'System.Management.Automation.PSCustomObject' = 'jsonb'
        'object'                                      = 'text'
        'Object[]'                                    = 'jsonb'
        'System.Object[]'                             = 'jsonb'
        'guid'                                        = 'uuid'
        'datetime'                                    = 'timestamp without time zone'
        'decimal'                                     = 'double precision'
        'long'                                        = 'bigint'
        'single'                                      = 'double precision'
        'System.String'                               = 'text'
        'double'                                      = 'double precision'
        'System.Int32'                                = 'integer'
        'System.DateTime'                             = 'timestamp without time zone'
        'ipaddress'                                   = 'inet'
        'uint32'                                      = 'bigint'
        'System.Int64'                                = 'bigint'
        'System.Decimal'                              = 'numeric'
        'byte'                                        = 'integer'
        'System.Net.IPAddress'                        = 'inet'
        'System.Double'                               = 'double precision'
        'macaddress'                                  = 'macaddr'
        'string[]'                                    = 'text'

    }

    $DataTable2 = New-Object System.Data.DataTable
    $DataTable2.TableName = 'Convert'

    #Column 1 - DataType
    $column = New-Object System.Data.DataColumn
    $column.DataType = [System.Type]::GetType('System.String')
    $column.ColumnName = 'DataType';
    $DataTable2.Columns.Add($column);
    #Column 1 - PGType
    $column = New-Object System.Data.DataColumn
    $column.DataType = [System.Type]::GetType('System.String')
    $column.ColumnName = 'PGType';
    $DataTable2.Columns.Add($column);

    foreach ($entry in $convert.GetEnumerator()) { 
        [void] $DataTable2.Rows.Add($entry.key, $entry.value)
    }


    # Datagridview
    $DGV = New-Object System.Windows.Forms.DataGridView
    #$DGV.AutoSize = $true
    #$DGV.Anchor = [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top
    $DGV.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top
    $DGV.Location = New-Object System.Drawing.Size(0, 100) 
    $DGV.Size = New-Object System.Drawing.Size(480, 550)
    #$DGV.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",10,0,3,1)
    $DGV.BackgroundColor = '#ffffffff'
    $DGV.BorderStyle = 'Fixed3D'
    #$DGV.AlternatingRowsDefaultCellStyle.BackColor = "#ffe6e6e6"
    $DGV.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $DGV.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::AllCells
    $DGV.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $DGV.ClipboardCopyMode = 'EnableWithoutHeaderText'
    $DGV.AllowUserToOrderColumns = $True
    $DGV.DataSource = $DataTable1
    $DGV.AutoGenerateColumns = $False
    $objForm.Controls.Add($DGV)

    # Datagridview columns
    $Column1 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $Column1.Name = 'Property'
    $Column1.HeaderText = 'Property'
    $Column1.DataPropertyName = 'Property'
    $Column1.AutoSizeMode = 'Fill'


    $Column2 = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
    $Column2.Name = 'PGType'
    $Column2.HeaderText = 'Data Type'
    $Column2.DataSource = $DataTable2
    $Column2.ValueMember = 'DataType'
    $Column2.DisplayMember = 'PGType'
    $Column2.DataPropertyName = 'DataType'

    $DGV.Columns.AddRange($Column1, $Column2)



    [void] $objForm.ShowDialog()

    if ($CancelButtonClicked -eq $true) {
        Write-Host 'Table creation cancelled.'
        exit
    }

    $fields = @()
    foreach ($row in $dgv.SelectedRows) {
        $fields += [PSCustomObject]@{
            Name  = $row.cells[0].Value
            Value = $row.cells[1].FormattedValue
        }
    }

    $pkey = $listbox2.CheckedItems
    $table_name = $objTextBox1.Text
    $schema_name = $objTextBox2.SelectedItem

    $table = [PSCustomObject]@{
        'Fields'     = $fields
        'PKey'       = $pkey
        'TableName'  = $table_name
        'SchemaName' = $schema_name
    }

    return $table
}

Function Write-PGSQLLog {

    <#
.SYNOPSIS
    Writes a log to a Postgresql DB
.DESCRIPTION
    Writes a log in a format similar to CMTrace to public.powershell_log, useful for tracking scripts and an alternative to using Transcript
.EXAMPLE

    Write an informational log from the current function

    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    
#>



    [CmdletBinding()]
    Param( 

        #The source log
        [parameter(Mandatory = $True)]
        [String]$Log,
    
        #The information to log
        [parameter(Mandatory = $True)]
        [String]$Value,
    
        #The source of the error
        [parameter(Mandatory = $True)]
        [String]$Component,
    
        #The severity (1 - Information, 2- Warning, 3 - Error)
        [parameter(Mandatory = $True)]
        [ValidateSet(1, 2, 3)]
        [int]$Severity,

        [parameter(Mandatory = $False)]
        [String]$Schedule = 'Manual'
    )

    begin {
        Connect-PGSQLServer
    }
    process {
        $SeverityTable = @{
            1 = 'Information'
            2 = 'Warning'
            3 = 'Error'
        }

        $record = [PSCustomObject]@{
            timestamp = $(Get-Date).ToUniversalTime()
            log       = $log
            component = $Component
            value     = $value
            context   = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
            severity  = $SeverityTable.Item($Severity)
            pid       = $pid
            schedule  = $schedule
        }
        Invoke-PGSqlQuery -Type Insert -InputObject $record -OnConflict 'Do Nothing' -Schema 'public' -Table 'powershell_log' -Truncate $false
    }
    end {
        Disconnect-PGSQLServer
    }

}
Function Get-PGSQLInsertLog {
    Remove-Item -Path .\insert_query.sql -Force -Confirm:$false -ErrorAction SilentlyContinue
    $PgInsertQuery > insert_query.sql
    code insert_query.sql
}


Function Invoke-PGSqlQuery {
    param (
        [Parameter(Position = 0)]
        [ValidateSet('Select', 'Insert', 'Truncate')]
        [string]
        $Type
    )
    DynamicParam {
        if ($Type -eq 'Select') {
            $SelectAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SelectAttribute.Mandatory = $true
            $SelectAttribute.HelpMessage = 'Enter a select statement:'
            $SelectAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SelectAttributeCollection.Add($SelectAttribute)
            $SelectAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $SelectParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Query', [string], $SelectAttributeCollection)
            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Query', $SelectParam)
            return $paramDictionary
        }
        if ($Type -eq 'Insert') {
            
            $InputObjectAttribute = New-Object System.Management.Automation.ParameterAttribute
            $InputObjectAttribute.Mandatory = $true
            $InputObjectAttribute.HelpMessage = 'Enter the InputObject:'
            $InputObjectAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $InputObjectAttributeCollection.Add($InputObjectAttribute)
            $InputObjectAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $InputObjectParam = New-Object System.Management.Automation.RuntimeDefinedParameter('InputObject', [System.Object], $InputObjectAttributeCollection)

            $SchemaAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SchemaAttribute.Mandatory = $true
            $SchemaAttribute.HelpMessage = 'Enter the schema name:'
            $SchemaAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SchemaAttributeCollection.Add($SchemaAttribute)
            $SchemaParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Schema', [string], $SchemaAttributeCollection)

            $TableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TableAttribute.Mandatory = $true
            $TableAttribute.HelpMessage = 'Enter the table name:'
            $TableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TableAttributeCollection.Add($TableAttribute)
            $TableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Table', [string], $TableAttributeCollection)

            $OnConflictValidateArray = @('Do Nothing', 'Set Excluded', 'null')
            $OnConflictAttribute = New-Object System.Management.Automation.ParameterAttribute
            $OnConflictAttribute.Mandatory = $true
            $OnConflictAttribute.HelpMessage = 'Enter the conflict statement:'
            $OnConflictAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $OnConflictAttributeCollection.Add($OnConflictAttribute)
            $OnConflictAttributeCollection.Add((New-Object System.Management.Automation.ValidateSetAttribute($OnConflictValidateArray)))
            $OnConflictParam = New-Object System.Management.Automation.RuntimeDefinedParameter('OnConflict', [string], $OnConflictAttributeCollection)

            $TruncateTableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TruncateTableAttribute.Mandatory = $true
            $TruncateTableAttribute.HelpMessage = 'Truncate table?:'
            $TruncateTableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TruncateTableAttributeCollection.Add($TruncateTableAttribute)
            $TruncateTableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Truncate', [bool], $TruncateTableAttributeCollection)

            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('InputObject', $InputObjectParam)
            $paramDictionary.Add('Schema', $SchemaParam)
            $paramDictionary.Add('Table', $TableParam)
            $paramDictionary.Add('OnConflict', $OnConflictParam)
            $paramDictionary.Add('Truncate', $TruncateTableParam)
         
            return $paramDictionary
        }
        if ($Type -eq 'Truncate') {
             
            $SchemaAttribute = New-Object System.Management.Automation.ParameterAttribute
            $SchemaAttribute.Mandatory = $true
            $SchemaAttribute.HelpMessage = 'Enter the schema name:'
            $SchemaAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $SchemaAttributeCollection.Add($SchemaAttribute)
            $SchemaAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $SchemaParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Schema', [string], $SchemaAttributeCollection)

            $TableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TableAttribute.Mandatory = $true
            $TableAttribute.HelpMessage = 'Enter the table name:'
            $TableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TableAttributeCollection.Add($TableAttribute)
            $TableAttributeCollection.Add((New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute))
            $TableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Table', [string], $TableAttributeCollection)
 
            $TruncateTableAttribute = New-Object System.Management.Automation.ParameterAttribute
            $TruncateTableAttribute.Mandatory = $true
            $TruncateTableAttribute.HelpMessage = 'Truncate table?:'
            $TruncateTableAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $TruncateTableAttributeCollection.Add($TruncateTableAttribute)
            $TruncateTableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Truncate', [bool], $TruncateTableAttributeCollection)

            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Schema', $SchemaParam)
            $paramDictionary.Add('Table', $TableParam)
            $paramDictionary.Add('Truncate', $TruncateTableParam)

            return $paramDictionary
        }
    }

    begin {
        Connect-PGSQLServer
    }


    process {
        switch ($Type) {
            'Select' { 
                Invoke-PGSQLSelect -Query $PsBoundParameters.Query
                break
            }
            'Insert' { 
                Invoke-PGSQLInsert -InputObject $PsBoundParameters.InputObject -OnConflict $PsBoundParameters.OnConflict -Schema $PsBoundParameters.Schema -Table $PsBoundParameters.Table -Truncate $PsBoundParameters.Truncate
                break
            }
            'Truncate' {
                if ($PsBoundParameters.Truncate -eq $true) {
                    Invoke-PGSQLTruncate -Schema $PsBoundParameters.Schema -Table $PsBoundParameters.Table
                }
                else { Write-Host 'TruncateTable not true' }
                break
            }
        }
    }
    end {
        Disconnect-PGSQLServer
    }
}