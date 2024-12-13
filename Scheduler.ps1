[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('15Minute', 'Hourly', 'Daily')]
    [string]
    $Schedule
)

$global:rootdir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

$Env:PSModulePath = $Env:PSModulePath+";$rootdir\Modules"
#$Env:PSModulePath = $Env:PSModulePath+";$pwd\Modules"
#Import-Module DataCollector.TM -Force
#Invoke-DataCollection -Schedule $Schedule