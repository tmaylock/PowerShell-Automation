

Function Get-PlannerPlans {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $TeamIDs
    )
 
    $allplans = foreach ($TeamID in $TeamIDs) {
        $url = "https://graph.microsoft.com/v1.0/groups/$TeamID/planner/plans"
        (Invoke-RestMethod -Headers (Get-MSGraphDelegatedAuthHeader) -Uri $Url -Method Get).value  | Select-Object id,owner,title,@{Name='groupid';Expression={$TeamID}}
    } 
    if ($allplans) {
        Invoke-PGSqlQuery -Type Insert -InputObject $allplans -OnConflict 'Do Nothing' -Schema 'planner' -Table 'plans' -Truncate $true
    }
}


Function Get-PlannerBuckets {
    $plans = Invoke-PGSqlQuery -Type Select -Query 'select id from planner.plans' 
    $chunks = Get-Chunks -InputObject $plans -SplitSize 20

    $allbuckets = foreach ($chunk in $chunks) {
        $json = @()
        foreach ($plan in $chunk) {
            $json += New-Object -TypeName PSObject -Property @{
                'id'     = $plan.id
                'method' = 'GET'
                'url'    = "/planner/plans/$($plan.id)/buckets"
            }
        }
        $jsonDoc = [pscustomobject]@{requests = $json } | ConvertTo-Json

        $result = Get-MsGraphBatch -Uri "https://graph.microsoft.com/v1.0/`$batch" -jsonDoc $jsonDoc -Headers (Get-MSGraphDelegatedAuthHeader)
        $result.responses.body.value | Select-Object id, name, planId

    }
    if ($allbuckets) {
        Invoke-PGSqlQuery -Type Insert -InputObject $allbuckets -OnConflict 'Do Nothing' -Schema 'planner' -Table 'buckets' -Truncate $true
    }
}

Function Get-PlannerTasks {
    $plans = Invoke-PGSqlQuery -Type Select -Query 'select id from planner.plans'
    $chunks = Get-Chunks -InputObject $plans.id -SplitSize 20
    
    $alltasks = foreach ($chunk in $chunks) {
        $json = @()
        foreach ($plan in $chunk) {
            $json += New-Object -TypeName PSObject -Property @{
                'id'     = $plan
                'method' = 'GET'
                'url'    = "/planner/plans/$plan/tasks?`$expand=details"
            }
        }
       
        $jsonDoc = [pscustomobject]@{requests = $json } | ConvertTo-Json
        $result = Get-MsGraphBatch -Uri "https://graph.microsoft.com/v1.0/`$batch" -jsonDoc $jsonDoc -Headers (Get-MSGraphDelegatedAuthHeader)
        $result.responses.body.value
    }
    
    $properties = @(
        'planid',
        'bucketid',
        'title',
        'percentcomplete',
        'startdatetime',
        'createddatetime',
        'duedatetime',
        'completeddatetime',
        'checklistitemcount',
        'activechecklistitemcount',
        'id',
        @{name = 'appliedcategories'; expression = { $_.appliedcategories | ConvertTo-Json -Compress -WarningAction SilentlyContinue } },
        @{name = 'assignments'; expression = { $_.assignments | ConvertTo-Json -Compress -WarningAction SilentlyContinue } },
        @{name = 'description'; expression = { $_.Details.Description.Trim() } }
    )


    $inputobject = $alltasks | Select-Object -Property $properties

    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'planner' -Table 'tasks' -Truncate $true


}





Function Get-MsGraphBatch {

    param (
        [parameter(Mandatory = $true)]
        $Headers,
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $true)]
        $jsonDoc
    )

    if ($Headers) {

        $QueryResults = @()
        $Results = ''
        $StatusCode = ''

        do {
            $Results = Invoke-RestMethod -Headers $Headers -Uri $Uri -UseBasicParsing -Method 'POST' -ContentType 'application/json' -Body $jsonDoc
            $StatusCode = $Results.responses.Status

            if (429 -in $StatusCode) {
                $retryafter = 30
                if ($Results.responses.headers.'Retry-After') {
                    $retryafter = ($Results.responses.headers.'Retry-After' | Sort-Object)[-1]
                }   
                Write-Warning "Got throttled by Microsoft. Sleeping for $retryafter seconds..."
                $delay = $retryafter
                while ($delay -ge 0) {
                    Write-Progress -Activity 'MS Graph Throttling' -SecondsRemaining $delay
                    Start-Sleep -Seconds 1
                    $delay -= 1
                }
            }
        } 
        while (429 -in $StatusCode)

        if ($Results.value) {
            $QueryResults += $Results.value
        }
        else {
            $QueryResults += $Results
        }
        $QueryResults
    }
    else {
        Write-Error 'No Headers'
    }
}


Function Invoke-PlannerScheduledFunction {
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
            # Your teams that you want to grab planner plans from, use the ID 
            $TeamIDs = @('', '')
            Write-Output 'Get-PlannerPlans'; Get-PlannerPlans -TeamIDs $TeamIDs
            Write-Output 'Get-PlannerBuckets'; Get-PlannerBuckets
            Write-Output 'Get-PlannerTasks'; Get-PlannerTasks
        }
    }

}


