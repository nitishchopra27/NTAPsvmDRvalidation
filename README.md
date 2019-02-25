# NTAPsvmDRvalidation

## Introduction
This document describes the PowerShell script implemented within the NetApp Hosted environment. This script is designed to compare configurations on Production and DR clusters/vservers to enable the NSO team to report on any discrepancies in the DR configurations.

## Script Details

### Input Parameters
  * prdClusters
  * drClusters
  
Although both the input parameters are array variables. The script expects to have one value in each array.
prdClusters: production cluster name/ip
drClusters: DR cluster name/ip

### Logging
The script creates two log files (csv and html). The log files are created in a log folder where the script is stored.

### Functions
**Import-Credentials**
This function imports username and password of the Service account used to run the script.
The encrypted username and password are stored in a secure location in Windows Registry.

**Check-LoadedModule**
This function checks if a Powershell module is loaded, else it loads the module.
This function is used to load Data ONTAP module before running any powershell cmdlets on the storage clusters.

**Connect-Cluster**
This function connects to the storage cluster using the credentials pulled from Import-Credentials function.

**Write-ErrMsg**
This function is used for debug purpose only. The script does not use this function in any form to perform comparisons.

**Write-Msg**
This function is used for debug purpose only. The script does not use this function in any form to perform comparisons.

**Write-Log**
This function is used to write to a Log file.
This function accepts the following parameters:
  * Message: Comments you want to save in the log file
  * Severity: Error, Information, Success

**Create-DataBase**
This is the main function of the script which collects all information from a cluster and stores the collected data in a multi-level hash with custom PSObjects.
This function accepts the following parameters:
  * clusters: name/ip of Production storage cluster
  * env: environment (prd or dr)
  * peerclusters: name/ip of the DR storage cluster.  

### Data Comparisons
The script performs the following comparisons on both PRD and DR SVMs
  * Cluster peer relationship
  * Cron Schedules

The script performs the following comparisons on both PRD and DR SVMs
  * DNS
  * Vserver configurations
    * Type
    * Name Service Switch
    * Language
    * Admin State
    * Snapshot Policy
    * Protocol allowed (CIFS/NFS)
    * Operational State
  * Vserver Peering
  * Gateway
  * Domain Controller Connectivity
  * Volume configurations
    * State
    * Snapshot Reserve Perentage
    * Security style
    * Dedupe state
    * Snapshot Auto delete enabled
    * Max autosize
  * CIFS Shaares and Configurations
    * Number of shares on Prd and DR Vservers
    * Share Name
    * Junction Path
    * Share Comments
    * Share Properties
  * CIFS User-Group Members
  * Snapmirrors
  * Data Lifs
    * Lif Role
    * Lif Status
    * Lif Protocols
  * Anti-Virus Lifs
    * Lif Role
    * Lif Status
    * Lif Protocols
    
### HTML Report
The log file created by the scipt is read and converted to an HTML file which is then sent via email to ng-westpac-ops groups.

### Examples
PS E:\ssh> .\Get-DRValidation.ps1 -prdClusters snowy -drClusters thunder
