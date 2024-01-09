[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('15Minute', 'Hourly', 'Daily','Skip')]
    [string]
    $Schedule
)

$global:rootdir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

$Env:PSModulePath = $Env:PSModulePath+";$rootdir\Modules"
#Import-Module DataCollector.TM -Force
#Invoke-DataCollection -Schedule $Schedule