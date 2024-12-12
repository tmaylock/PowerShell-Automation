# About
A collection of PowerShell modules for extracting data from various sources.

# Getting Started

## 3rd Party Modules and Binaries
- 3rd Party Modules are required for most of the functions. They must be installed before attempting to load other modules. (See 3rdPartyModules.ps1)
- Dll's and executables are required for a few functions:
  - CheckMK Module: ncat.exe for pulling data out of Check_MK ([need to install nmap](https://nmap.org/dist/nmap-7.92-setup.exe))
  - SharedFunctions Module: Microsoft.Identity.Client for using "Delegated Auth" to authenticate as an actual user (useful for MS Planner - [link](https://www.nuget.org/api/v2/package/Microsoft.Identity.Client/4.58.1))
  - Switches Module: SharpSnmpLib for SNMP communication (download from [here](https://www.nuget.org/api/v2/package/Lextm.SharpSnmpLib/12.5.2) and use SharpSnmpLib.dll from the folder "lib\netstandard2.0")
 
## Automating the Process
- Secret Store
  - Comment the "Microsoft.PowerShell.SecretStore" module out of "RequiredModules" to make it easier to run manually.
  - Read the notes under the "Get-SecretFromVault" function.
  - Consider replacing this with [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell), it's much easier to use and more portable.
- Create 3 scheduled tasks set to run as the user with granted permissions, run whether or not the user is logged on or not, with the highest privileges.
  - Scheduler.ps1 -Schedule '15Minute'
  - Scheduler.ps1 -Schedule 'Hourly'
  - Scheduler.ps1 -Schedule 'Daily'
- DataCollector
  - This module runs all the PS Thread Jobs for the modules. Uncomment each "Start-ThreadJob" to start using them.
- Variables
  - Configure the variables at the end of "SharedFunctions.TM.psm1"
- Postgresql
  - Tested with version 15 of postgres (should work with 16).
  - Optionally (but highly recommended) install [TimescaleDB extension](https://docs.timescale.com/self-hosted/latest/install/)
  - Configure pg_hba.conf to allow the PowerShell script to connect.

# Modules List:
- ActiveDirectory
- Azure
- CheckMK
- CheckPoint
- Commvault
- Compliance (very custom, but useful)
- DataCollector (main module that invokes all other modules)
- DefenderForEndpoint
- Grafana
- Metrics (should be moved to an Intune module...)
- MSGraph
- MSGraphReports (various M365 reports from https://graph.microsoft.com/v1.0/reports)
- Network (collect info from Cisco routers via Ansible)
- Office365
- OME (Dell OpenManage Enterprise)
- Planner (Microsoft Planner)
- Postgresql (required by all modules)
- PowerAutomate
- Qualys
- SCCM
- Sentinel
- SharedFunctions (required by all modules)
- Sharepoint
- Switches
- WSUS
