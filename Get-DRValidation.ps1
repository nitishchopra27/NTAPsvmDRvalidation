<#
.SYNOPSIS
  Get-DRValidation.ps1 performs a DR Validation on NetApp Data ONTAP storage clusters.

.DESCRIPTION
   The script compares the following settings:
   
   CLUSTER SETTINGS:
   Cluster peer relationship
   Cron Schedules

   VSERVER SETTINGS:
   DNS
   Vserver configurations
       Type
       Name Service Switch
       Language
       Admin State
       Snapshot Policy
       Protocol allowed (CIFS/NFS)
       Operational State
   Vserver Peering
   Gateway
   Domain Controller Connectivity
   Volume configurations
        State
        Snapshot Reserve Perentage
        Security style
        Dedupe state
        Snapshot Auto delete enabled
        Max autosize
   CIFS shares and configurations
        Number of shares on Prd and DR Vservers
        Share Name
        Junction Path
        Share Comments
        Share Properties
   CIFS User-Group Members
   Snapmirrors
   Data Lifs
        Lif Role
        Lif Status
        Lif Protocols
   Anti-Virus Lifs
        Lif Role
        Lif Status
        Lif Protocols

   Send email to Recepients with data collected by this script as HTML body

   This script has been successfully tested on DATA ONTAP 9.1P5 and 9.1P8

.PARAMETER prdClusters
  Production NetApp cluster name/ip
  
.PARAMETER drClusters
  DR NetApp cluster name/ip

.INPUTS
  The script requires DataONTAP Module to be present on the Windows host.

.OUTPUTS
  The script log file is stored in the Logs folder in current directory where the script is run from

.NOTES
  Version:        1.0
  Author:         Nitish Chopra
  Creation Date:  08/12/2017
  Purpose/Change: Validate DR configuration

.EXAMPLE
  PS E:\ssh\L080898> .\Get-DRValidation.ps1 -prdClusters snowy -drClusters thunder
#>
#---------------------------------------------------------[Script Parameters]------------------------------------------------------
Param (
  #Script parameters go here
  [Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter the Location of file with storage clusters")] 
  [array]$prdClusters,
  [Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter the Location of file with storage clusters")] 
  [array]$drClusters,
  [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="Get Date and Time for the Log File")]
  [string]$timer = (Get-Date -Format yyyy-MM-dd-hhmm)
)
#----------------------------------------------------------[Declarations]----------------------------------------------------------
#Script Version
$sScriptVersion = '1.0'
[string]$pcluster = $prdClusters | Select-Object -First 1
[string]$dcluster = $drClusters | Select-Object -First 1
[String]$scriptPath     = $PSScriptRoot
[String]$logName        = "Comapre-SVMs"+"-"+"$pcluster"+"-"+"$dcluster"+".csv"
[String]$scriptLogP     = $scriptPath + "\Logs"
[String]$scriptLogPath  = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $logName
[String]$htmlName        = "Comapre-SVMs"+"-"+"$pcluster"+"-"+"$dcluster"+".html"
[String]$scriptHTMLLogPath  = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $htmlName
[string]$prddbLogFile   = "prddb-"+$pcluster+".json"
[string]$prddbLogPath   = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $prddbLogFile
[string]$drdbLogFile   = "drdb-"+$dcluster+".json"
[string]$drdbLogPath   = $scriptPath + "\Logs\" + (Get-Date -uformat "%Y-%m-%d-%H-%M") + "-" + $drdbLogFile
#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Import-Credentials{
   <#
   .SYNOPSIS
   This function decrypts registry key values.
   .DESCRIPTION
   Used Microsoft's DPAPI to decrypt binary values.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .PARAMETER
   RegistryPath Accepts a String containing the registry path.
   .EXAMPLE
   Import-Credentials -registryPath "HKLM\Software\Scripts" -registryValue "Value"
   .NOTES
   The example provided decryptes the value of the registry key "HKLM\Software\Scripts\Value"
   Credentials can only be decrypted by the same user account that was used to export them.
   See the Microsoft DPAPI documentation for further information
   .LINK
   http://msdn.microsoft.com/en-us/library/ms995355.aspx
   http://msdn.microsoft.com/en-us/library/system.security.cryptography.protecteddata.aspx
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryPath,
      [Parameter(Position=1,
         Mandatory=$True,
         ValueFromPipeLine=$True,
         ValueFromPipeLineByPropertyName=$True)]
      [String]$registryValue
   )
   #'---------------------------------------------------------------------------
   #'Decrypt value from binary registry key
   #'---------------------------------------------------------------------------
   $keyPath = "HKLM\$registryPath\$registryValue"
   Try{
      [void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
      $secret    = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath).GetValue($registryValue)
      $decrypted = [System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($secret, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
   }Catch{
      Write-Warning -Message $("Failed Reading Registry Key ""$keyPath"". Error " + $_.Exception.Message)
      $decrypted = ""
   }
   Return $decrypted;
}
function Check-LoadedModule {
  Param(
    [parameter(Mandatory = $true)]
    [string]$ModuleName
  )
  Begin {
    #Write-Log -Message "*** Importing Module: $ModuleName"
  }
  Process {
    $LoadedModules = Get-Module | Select Name
    if ($LoadedModules -notlike "*$ModuleName*") {
      try {
        Import-Module -Name $ModuleName -ErrorAction Stop
      }
      catch {
        Write-Log -Message "Could not find the Module on this system. Error importing Module" -Severity Error
        Break
      }
    }
  }
  End {
    If ($?) {
      #Write-Log -Message "Module $ModuleName is imported Successfully" -Severity Success
    }
  }
}
function Connect-Cluster {
  Param (
    [parameter(Mandatory = $true)]
    [string]$strgCluster
  )
  Begin {
    #Write-Log -Message "*** Connecting to storage cluster $strgCluster"
  }  
  Process {  
    try {
      Add-NcCredential -Name $strgCluster -Credential $ControllerCredential
      Connect-nccontroller -Name $strgCluster -HTTPS -Timeout 600000 -ErrorAction Stop | Out-Null 
    }
    catch {
      Write-Log -Message "Failed Connecting to Cluster $strgCluster : $_." -Severity Error
      Break
    }
  }
  End {
    If ($?) {
      #Write-Log -Message  "Connected to $strgCluster" -Severity Success
    }
  }
}
function Write-ErrMsg ($msg) {
    $fg_color = "White"
    $bg_color = "Red"
    Write-host $msg -ForegroundColor $fg_color -BackgroundColor $bg_color
}
function Write-Msg ($msg) {
    $color = "yellow"
    Write-host ""
    Write-host $msg -foregroundcolor $color
    Write-host ""
}
function Write-Log {
     [CmdletBinding()]
     param(
         [Parameter()]
         [ValidateNotNullOrEmpty()]
         [string]$Message,
 
         [Parameter()]
         [ValidateNotNullOrEmpty()]
         [ValidateSet('Information','Success','Error')]
         [string]$Severity = 'Information'
     )
 
     [pscustomobject]@{
         #"Time" = (Get-Date -f g);
         "Severity" = $Severity;
         "Message" = $Message;
     } | Export-Csv -Path $scriptLogPath -Append -NoTypeInformation
 }
function Create-Database {
  Param(
    [parameter(Mandatory = $true)]
    [array]$clusters,
    [parameter(Mandatory = $true)]
    [string]$env,
    [parameter(Mandatory = $true)]
    [array]$peerclusters
  )
  Begin {
    #Write-Log -Message "*** Start collecting data for : $env"
  }
  Process {
        $db = @{
        "cluster" = @{};
        "cluster_peer" = @{};
        "vserver" = @{};
        "volume" = @{};
        "export_policy" = @{};
        "export_rule" = @{};
        "port" = @{};
        "cifs_share" = @{};
        "local_group" = @{};
        "dns" = @{};
        "schedule" = @{};
        "snapmirror_policy" = @{};
        "snapmirror_policy_rule" = @{};
        "snapmirror_dst" = @{};
        "snapmirror_src" = @{};
        "snapshot_policy" = @{};
        "snapshot_policy_schedule" = @{};
        "efficiency_policy" = @{};
        "vserver_peer" = @{};
        "vserver_dataLif" = @{};
        "vserver_avLif" = @{};
        "route" = @{};
        "dc" = @{};
    }
    $cpeer = $peerclusters | Select-Object -First 1
    $clusters | ForEach-Object {
    $cluster = $_
    Connect-Cluster -strgCluster $cluster
        
    # get cluster info
    try {
        $info = Get-NcCluster -EA Stop
    }
    catch {
       Write-Log -Message "Could not run Get-NcCluster: $_.Exception.Message" -Severity Error
    }
    $addr = $info.NcController.Address.IpAddressToString
    $newcluster = [PSCustomObject]@{
        "name" = $info.ClusterName;
        "location" = $info.ClusterLocation;
        "primary_address" = $addr;
        "serial_number" = $info.ClusterSerialNumber;
    }
    $db["cluster"][$cluster] = $newcluster
    
    # get cluster peer info
    try {
        $cpeerinfo = Get-NcClusterPeer -Name $cpeer -EA Stop
    }
    catch {
        Write-Log -Message "Could not run Get-NcClusterPeer: $_.Exception.Message" -Severity Error
    }
    $newcpperinfo = [PSCustomObject]@{
        "peer_cluster" = $cpeerinfo.ClusterName;
        "availability" = $cpeerinfo.Availability;
        "is_healthy" = $cpeerinfo.IsClusterHealthy
    }
    $db["cluster_peer"][$cluster] = $newcpperinfo

    # get vserver info
    if ($env -eq 'prd') {
        try {
            $vservers = Get-NcVserver -ErrorAction Stop | ?{$_.Vserver -notlike "*DR" -and $_.VserverType -eq "data"}
        }
        catch {
            Write-Log -Message "Could not run Get-NcVserver for Prd cluster: $_.Exception.Message" -Severity Error
        }
    }
    elseif ($env-eq 'dr') {
        try {
            $vservers = Get-NcVserver -ErrorAction Stop | ?{$_.Vserver -like "*DR*" -and $_.VserverType -eq "data"}
        }
        catch {
            Write-Log -Message "Could not run Get-NcVserver for DR cluster: $_.Exception.Message" -Severity Error
        }
    }
    $vservers | % {
	    $vserver = $_
        $vserverName = $vserver.VserverName
	    $protos = $vserver.AllowedProtocols
	    $nsswitch = $null
	    if (-not ([string]::IsNullOrEmpty($vserver.NameServerSwitch))) {
		    $nsswitch = $vserver.NameServerSwitch -join ","
	    }
	    $newvserver = [PSCustomObject]@{
            "name" = $vserver.VserverName;
            "type" = $vserver.VserverType;
            "name_service_switch" = $nsswitch;
            "language" = $vserver.Language;
            "comment" = $vserver.Comment;
            "admin_state" = $vserver.State;
            "snapshot_policy" = $vserver.SnapshotPolicy;
            "nfs_allowed" = $([bool] ($protos -contains "nfs"));
            "cifs_allowed" = $([bool] ($protos -contains "cifs"));
            "operational_state" = $vserver.OperationalState;
            "RootVolume" = $vserver.RootVolume;
	    }
        $db["vserver"][$vserverName] = $newvserver

        # get cifs shares info
        if ($env -eq 'prd') {
            try {
                $cifsshares = Get-NcCifsShare -VserverContext $vserverName -ErrorAction Stop | ?{$_.cifsserver -notlike "*DR" -and $_.path -ne '/'}
            }
            catch {
                Write-Log -Message "Could not run Get-NcCifsShare for $vserverName : $_.Exception.Message" -Severity Error
            }
        }
        elseif ($env -eq 'dr') {
            try {
                $cifsshares = Get-NcCifsShare -VserverContext $vserverName -ErrorAction Stop | ?{$_.cifsserver -like "*DR" -and $_.path -ne '/'}
            }
            catch {
                Write-Log -Message "Could not run Get-NcCifsShare for $vserverName : $_.Exception.Message" -Severity Error
            }
        }
        $cifsshares | % {
	        $share = $_
            $shareId = $vserverName+":"+$share.ShareName
	        $newshare = [PSCustomObject]@{
		        "name" = $share.ShareName;
		        "path" = $share.Path;
		        "comment" = $share.Comment;
		        "share_properties" = $($share.ShareProperties -join ",");
	        }
	        $db["cifs_share"][$shareId] = $newshare
	    } # End of Get-NcCifsShare
        
        # get data lif info
        @(Get-NcNetInterface -Vserver $vserverName -ErrorAction Stop | ?{($_.InterfaceName -like "*CIFS*") -or ($_.InterfaceName -like "*NFS*") }) | % {
	        $lif = $_
            $lifId = $vserverName+":"+$lif.InterfaceName
            $newlif = [PSCustomObject]@{
		        "name" = $lif.InterfaceName;
		        "role" = $lif.Role;
		        "status" = $lif.OperationalStatus;
		        "address" = $lif.Address;
		        "netmask" = $lif.Netmask;
		        "protocols" = $($lif.DataProtocols -join ",");
		        "failover_group" = $lif.FailoverGroup;
		        "failover_policy" = $lif.FailoverPolicy;
                "vserver" = $lif.Vserver;
	        }
            $db["vserver_dataLif"][$lifId] = $newlif
        } # End of Get-NcNetInterface (data lif)

        # get AV lif info
        @(Get-NcNetInterface -Vserver $vserverName -ErrorAction Stop | ?{$_.InterfaceName -like "*_AV_*"}) | % {
	        $avlif = $_
            $avlifId = $vserverName+":"+$avlif.InterfaceName
            $newavlif = [PSCustomObject]@{
		        "name" = $avlif.InterfaceName;
		        "role" = $avlif.Role;
		        "status" = $avlif.OperationalStatus;
		        "address" = $avlif.Address;
		        "netmask" = $avlif.Netmask;
		        "protocols" = $($avlif.DataProtocols -join ",");
		        "failover_group" = $avlif.FailoverGroup;
		        "failover_policy" = $avlif.FailoverPolicy;
                "vserver" = $avlif.Vserver;
	        }
            $db["vserver_avLif"][$avlifId] = $newavlif
        } # End of Get-NcNetInterface (av lif)

        # get gateway info
        try {
            $routeInfo = Get-NcNetRoute -Vserver $vserverName -EA stop | Where-Object {$_.Metric -le '20'}
        }
        catch {
            Write-Log -Message "Could not run Get-NcNetRoute for $vserverName : $_.Exception.Message" -Severity Error
        }
        $newrouteInfo = [PSCustomObject]@{
            "vserver" = $routeInfo.Vserver;
            "gateway" = $routeInfo.Gateway;
            "destination" = $routeInfo.Destination;
        }
        $db["route"][$vserverName] = $newrouteInfo

        <#
        # get domain controllers info
        $db["dc"][$vserverName] = @{}
        try {
            $dcTemplate = Get-NcCifsDomainServer -Template
            $dcTemplate.Status = "ok"
            $dcinfo = (Get-NcCifsDomainServer -VserverContext $vserverName -Query $dcTemplate -EA stop).Name
        }
        catch {
            Write-Log -Message "Could not run Get-NcCifsDomainServer for $vserverName : $_.Exception.Message" -Severity Error
        }
        $db["dc"][$vserverName] = $dcinfo
        #>

        # get volumes info
        $svmrootvol1 = $vserverName+"_root"
        $svmrootvol2 = "rootvol"
        if ($env -eq 'prd') {
            try {
                $volumesTemplate = Get-NcVol -Template
                Initialize-NcObjectProperty -Object $volumesTemplate -Name VolumeIdAttributes
                $volumesTemplate.VolumeIdAttributes.Type = "rw"
                $volumes = Get-NcVol -VserverContext $vserverName -Query $volumesTemplate -ErrorAction Stop | ?{($_.Name -ne $svmrootvol1) -and ($_.Name -ne $svmrootvol2)}
            }
            catch {
                Write-Log -Message "Could not run Get-NcVol for $vserverName : $_.Exception.Message" -Severity Error
            }
        }
        elseif ($env -eq 'dr') {
            try {
                $volumesTemplate = Get-NcVol -Template
                Initialize-NcObjectProperty -Object $volumesTemplate -Name VolumeIdAttributes
                $volumesTemplate.VolumeIdAttributes.Type = "dp"
                $volumes = Get-NcVol -VserverContext $vserverName -Query $volumesTemplate -ErrorAction Stop | ?{$_.Name -ne $svmrootvol}
            }
            catch {
                Write-Log -Message "Could not run Get-NcVol for $vserverName : $_.Exception.Message" -Severity Error
            }
        }
        $volumes | % {
            $vol = $_
            $volId = $vserverName+":"+$vol.Name
            $newvol = [PSCustomObject]@{
            "name" = $vol.Name;
            "state" = $vol.State;
            "junction_path" = $(if (-not ([string]::IsNullOrEmpty($vol.JunctionPath))) {$vol.JunctionPath} else {"-"});
            "snapshot_reserved_percent" = $vol.VolumeSpaceAttributes.PercentageSnapshotReserve;
            "style" = $style;
            "max_autosize_mb" = [int64]($vol.VolumeAutosizeAttributes.MaximumSize / 1MB);
            "security_style" = $vol.VolumeSecurityAttributes.Style;
            "snapshot_policy" = $vol.VolumeSnapshotAttributes.SnapshotPolicy;
            "language" = $vol.VolumeLanguageAttributes.LanguageCode;
            "dedupe_state" = $vol.VolumeSisAttributes.IsSisVolume;
            "auto_delete_enabled" = $($vol.VolumeSnapshotAutodeleteAttributes.IsAutodeleteEnabled);
            }
            $db["volume"][$volId] = $newvol
        } # End of Get-NcVol
        
        # get DNS info
        try {
            $dnsInfo = Get-NcNetDns -Vserver $vserverName -ErrorAction Stop
        }
        catch {
            Write-Log -Message "Could not run Get-NcNetDns for $vserverName : $_.Exception.Message" -Severity Error
        }
        $newdnsInfo = [PSCustomObject]@{
            "state" = $dnsInfo.DnsState;
            "domain" = $($dnsInfo.Domains -join ",");
            "nameServers" = $($dnsInfo.NameServers -join ",");
        }
        $db["dns"][$vserverName] = $newdnsInfo

        # get vserver peer info
        try {
            $VserverPeer = Get-NcVserver -Name $vserverName | Get-NcVserverPeer -EA stop
        }
        catch {
            Write-Log -Message "Could not run Get-NcVserverPeer for $vserverName : $_.Exception.Message" -Severity Error
        }
        $VserverPeerInfo = [PSCustomObject]@{
            "SourceVserver"   = $VserverPeer.Vserver;
            "PeerVserver"     = $VserverPeer.PeerVserver;
            "PeerCluster"     = $VserverPeer.PeerCluster;
            "PeerState"       = $VserverPeer.PeerState;
        }
        $db["vserver_peer"][$vserverName] = $VserverPeerInfo

        # get CIFS user-group Members
        $db["local_group"][$vserverName] = @{}
        try {
            $localGroup = (Get-NcCifsLocalGroup -Vserver $vserverName).GroupName
        }
        catch {
            Write-Log -Message "Could not run Get-NcCifsLocalGroup for $vserverName : $_.Exception.Message" -Severity Error
        }
        $localGroup | %{
            if ((Get-NcCifsLocalGroupMember -Vserver $vserverName -Name "$_").Member -ne $null) {
                $db["local_group"][$vserverName]["$_"] += (Get-NcCifsLocalGroupMember -Vserver $vserverName -Name "$_").Member
            }
        }

	} # End of Get-NcVserver
    
    # get snapmirror_src
    @(Get-NcSnapmirrorDestination -ErrorAction Stop) | ? { $_.RelationshipType -like "data_protection" -or $_.RelationshipType -like "extended_data_protection" } | %{
        $snap_s = $_
        $SourceLocation = $snap_s.SourceLocation
        $newsnap_src = [PSCustomObject]@{
            "SourceLocation" = $snap_s.SourceLocation;
            "SourceVolume" = $snap_s.SourceVolume;
            "DestinationLocation" =$snap_s.DestinationLocation;
            "DestinationVolume" = $snap_s.DestinationVolume;
        }
        $db["snapmirror_src"][$SourceLocation] = $newsnap_src
    }
    # get snapmirror_dst
    @(Get-NcSnapmirror -ErrorAction Stop) | ? { $_.RelationshipType -like "data_protection" -or $_.RelationshipType -like "extended_data_protection"} | %{
        $snap_d = $_
        $SourceLocation = $snap_d.SourceLocation
        $newsnap_dst = [PSCustomObject]@{
            "SourceLocation" = $snap_d.SourceLocation;
            "SourceVolume" = $snap_d.SourceVolume;
            "DestinationLocation" =$snap_d.DestinationLocation;
            "DestinationVolume" = $snap_d.DestinationVolume;
            "IsHealthy" = $snap_d.IsHealthy;
        }
        $db["snapmirror_dst"][$SourceLocation] = $newsnap_dst
    }
    # get snapshot policy
        @(Get-NcSnapshotPolicy -ErrorAction Stop | ? { $_.Policy -notlike "Snapshot*" -and $_.Policy -notlike "transition*"}) | % {
        $ssp = $_
        $policyname = $ssp.Policy
        if ($ssp.SnapshotPolicySchedules -ne $null) {
            $ssp.SnapshotPolicySchedules | % {
                $sspsched = $_
                $newsspsched = [PSCustomObject][ordered]@{
                   "snapshot_count" = $sspsched.Count;
                   "snapshot_prefix" = $sspsched.Prefix;
                   "snapmirror_label" = $sspsched.SnapmirrorLabel;
                   "snapshot_schedule" = $sspsched.Schedule;
                }
                $db["snapshot_policy"][$policyname] = $newsspsched
            }
          }
        } # End of Get-NCSnapshotPolicy
    # get cron schedule info
    @(Get-NcJobCronSchedule -EA Stop | ? {($_.JobScheduleName -notlike "*transition*") -and ($_.JobScheduleName -notlike "*CronJob_*")}) | % {
        $sched = $_
        $cronname = $sched.JobScheduleName
        $minutes = $null
        $hours = $null
        $months = $null
        $dow = $null
        $dom = $null
        if ($sched.Minute -ne $null) {
           $minutes = $($sched.Minute -join ",")
        }
        if ($sched.Hour -ne $null) {
           $hours = $($sched.Hour -join ",")
        }
        if ($sched.Month -ne $null) {
           $months = $($sched.Month -join ",")
        }
        if ($sched.Day -ne $null) {
           $dom = $($sched.Day -join ",")
        }
        if ($sched.DayOfWeek -ne $null) {
           $dow = $($sched.DayOfWeek -join ",")
        }
        $newsched = [PSCustomObject][ordered]@{
           "name" = $sched.JobScheduleName;
           "description" = $sched.JobScheduleDescription;
           "type" = "cron";
           "cron_days_of_month" = $dom;
           "cron_days_of_week" = $dow;
           "cron_hours" = $hours;
           "cron_minutes" = $minutes;
           "cron_months" = $months;
        }
        $db["schedule"][$cronname] = $newsched
       } # End of Get-NcJobCronSchedule
    } # End of $clusters array
    return $db
  } # End of Process loop
  End {
    If ($?) {
      #Write-Log -Message "Data Collection for $clusters Completed Successfully"
    }
  }
}
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'
[String]$registryPath = "Software\NetApp\Scripts\Syslog";
[String]$username     = Import-Credentials -registryPath $registryPath -registryValue "Key"
[String]$password     = Import-Credentials -registryPath $registryPath -registryValue "Value"
$ssPassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$ControllerCredential = New-Object System.Management.Automation.PsCredential($username,$ssPassword)
#-----------------------------------------------------------[Execution]------------------------------------------------------------
# Create Log Directory
if ( -not (Test-Path $scriptLogP) ) { 
       Try{
          New-Item -Type directory -Path $scriptLogP -ErrorAction Stop | Out-Null
       }
       Catch{
          Exit -1;
       }
}
Write-Log -Message "*** Comparing vservers on clusters $pcluster and $dcluster" -Severity Information

#Import Modules
Check-LoadedModule DataONTAP

#Write-Log -Message "*** Collecting data from $prdClusters"
$prddb = Create-Database -clusters $prdClusters -env "prd" -peerclusters $dcluster
#$prddb | ConvertTo-Json -Depth 4 | Out-File $prddbLogPath

#Write-Log -Message "*** Collecting data from $drClusters"
$drdb = Create-Database -clusters $drClusters -env "dr" -peerclusters $pcluster
#$drdb | ConvertTo-Json -Depth 4 | Out-File $drdbLogPath 

# List all SVMs with peer relations
Connect-Cluster -strgCluster $pcluster
$prdSVMsPeer = Get-NcVserverPeer | ?{$_.Vserver -notlike "*DR*"} | ?{$_.PeerVserver -like "*DR*"}
$prdSVMsPeerHash = @{}

# Create a hashtable of SVM peer relations
foreach ($svm in $prdSVMsPeer) {
    $svmName = $svm.Vserver
    $prdSVMsPeerHashInfo = [PSCustomObject]@{
        "Vserver"     = $svm.Vserver
        "Cluster"     = $prdCluster;
        "PeerVserver" = $svm.PeerVserver;
        "PeerCluster" = $svm.PeerCluster;
    }
    $prdSVMsPeerHash[$svmName] = $prdSVMsPeerHashInfo
}
#$prdSVMsPeerHash | ConvertTo-Json

Write-Log -Message "================================================"

# Compare Cluster peer relationship
Write-Log -Message "*** Comparing cluster peer relationship"
if (($($prddb.cluster_peer.$pCluster.availability) -eq 'available') -and ($($drdb.cluster_peer.$dCluster.availability) -eq 'available')) {
    if (($($prddb.cluster_peer.$pcluster.is_healthy) -eq $true) -and ($($drdb.cluster_peer.$dcluster.is_healthy) -eq $true) ) {
        Write-Log -Message "PASS: Clusters : $pcluster and $dcluster : are in peer relationship and HEALTHY" -Severity Success
    }
}
else {
    Write-Log -Message "Peer Relationship of clusters : $pcluster and $dcluster : is not healthy" -Severity Error
}

# Compare Cron Schedules
Write-Log -Message "*** Compare Cron Schedules"

$prddb.schedule.Keys |Where-Object { $drdb.schedule.keys -notcontains $_ }|ForEach-Object {
    Write-Log -Message "Schedule: $_ is not in $dcluster" -Severity Error
}
Write-Log -Message "Compared Cron Schedules on the clusters" -Severity Success

# Iterate Peer SVM hash
$prdSVMsPeerHash.GetEnumerator() | Sort-Object -property Key | %{ 
    Write-Log -Message "================================================"
    ($prdVserver, $prCluster, $drVserver, $drCluster) = ($($_.key), $($_.value.Cluster) ,$($_.value.PeerVserver), $($_.value.PeerCluster))
    #Write-Log -Message "Current hashtable is: $prdVserver" -Severity Information
    #Write-Log "Value of PeerVserver is: $drVserver" -Severity Information
    #Write-Log "Value of PeerCluster is: $drCluster" -Severity Information
    Write-Log -Message "*** Compare vservers $prdVserver and $drVserver"

    # Compare DNS
    Write-Log -Message "*** Comparing DNS Settings"
    If (($($prddb.dns.$prdVserver.nameServers) -ne $null) -and ($($drdb.dns.$drVserver.nameServers) -ne $null)) {
        If (($($prddb.dns.$prdVserver.state) -eq 'enabled') -and ($($drdb.dns.$drVserver.state) -eq 'enabled') ) {
            Write-Log -Message "PASS: DNS is configured on both $prdVserver and $drVserver SVMs" -Severity Success
        }
    }
    else {
        Write-Log -Message "DNS is not configured on either of the Vservers: $prdVserver $drVserver" -Severity Error
    }

    # Compare Vservers
    [int]$vservi = 0
    Write-Log -Message "*** Comparing Vservers"
    if ($($prddb.vserver.$prdVserver.type) -ne $($drdb.vserver.$drVserver.type)) {
        Write-Log -Message "$drVserver is of different Vserver type than : $($prddb.vserver.$prdVserver.type)" -Severity Error
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.name_service_switch) -ne $($drdb.vserver.$drVserver.name_service_switch)) {
        Write-Log -Message "$drVserver has different name service switch than : $($prddb.vserver.$prdVserver.name_service_switch)" -Severity Error
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.language) -ne $($drdb.vserver.$drVserver.language)) {
        Write-Log -Message "$drVserver has different vserver language than : $($prddb.vserver.$prdVserver.language)" -Severity Error
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.admin_state) -ne $($drdb.vserver.$drVserver.admin_state)) {
        Write-Log -Message "$drVserver has a different admin state than : $($prddb.vserver.$prdVserver.admin_state)" -Severity Error
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.snapshot_policy) -ne $($drdb.vserver.$drVserver.snapshot_policy)) {
         Write-Log -Message "$drVserver has different default snapshot policy than : $($prddb.vserver.$prdVserver.snapshot_policy)" -Severity Error
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.cifs_allowed) -eq $true) {
        if ($($drdb.vserver.$drVserver.cifs_allowed) -eq $false) {
        Write-Log -Message  "CIFS is not allowed in $drVserver" -Severity Error
        }
        else { $vservi++ }
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.nfs_allowed) -eq $true) {
        if ($($drdb.vserver.$drVserver.nfs_allowed) -eq $false) {
        Write-Log -Message "NFS is not allowed in $drVserver" -Severity Error
        }
        else { $vservi++ }
    }
    else { $vservi++ }
    if ($($prddb.vserver.$prdVserver.operational_state) -ne $($drdb.vserver.$drVserver.operational_state)) {
        Write-Log -Message "$drVserver operational state is not: $($prddb.vserver.$prdVserver.operational_state)" -Severity Error
    }
    else { $vservi++ }

    if ($vservi -ge 8) {
        Write-Log -Message "PASS : Both $prdVserver and $drVserver configurations are same" -Severity Success
    }

    # Compare Vserver Peer
    Write-Log -Message "*** Compare Vserver Peer"
    if (($($prddb.vserver_peer.$prdVserver.PeerState) -eq 'peered') -and ($($drdb.vserver_peer.$drVserver.PeerState) -eq 'peered')) {
        Write-Log -Message "PASS : $prdVserver and $drVserver are PEERED and HEALTHY" -Severity Success
    }
    else {
        Write-Log -Message "$prdVserver and $drVserver are not PEERED and UNHEALTHY" -Severity Error
    }

    # Compare Gateway information
    Write-Log -Message "*** Compare Gateway Information"
    if (($($prddb.route.$prdVserver.gateway) -ne $null) -and  ($($drdb.route.$drVserver.gateway) -ne $null)) {
        if($($prddb.route.$prdVserver.destination) -ne  $($drdb.route.$drVserver.destination)) {
            Write-Log -Message "$drVserver gateway configuration does not match Production" -Severity Error
        }
        else {
            Write-Log -Message "PASS : Routes on both vservers $prdVserver or $drVserver are configured" -Severity Success
        }
    }
    else {
        Write-Log -Message "Gateway information is missing on either of vservers $prdVserver or $drVserver" -Severity Error
    }

    <#
    # Compare Connectivity to Domain Controllers
    Write-Log -Message "*** Check Connectivity to Domain Controllers"
    # If CIFS protocol is enabled on the vserver then check for DC Connectivity
    If(($($drdb.dc.$drVserver).count -eq 0) -and ($($drdb.vserver.$drVserver.cifs_allowed) -eq $true))  {
        Write-Log -Message "$drVserver is not connected to any DC" -Severity Error
    }
    Elseif (($($drdb.dc.$drVserver).count -eq 0) -and ($($drdb.vserver.$drVserver.cifs_allowed) -eq $false)) {
        Write-Log -Message "DC connectivity not required. $drVserver does not have CIFS enabled" -Severity Success
    }
    #>

    # Compare volumes
    Write-Log -Message "*** Compare Volumes"
    $svmVols = $($prddb.volume.keys) | ? {$_ -like "*$prdVserver*"}
    if ($svmVols -ne $null) {
    $($prddb.volume.keys) | ? {$_ -like "*$prdVserver*"} | % {
        $prvolume = $_
        [int]$voli = 0
        ($prdsvm,$prdvolume) = $_.split(":")
        # check if there is a DR volume
        #if ($($prddb.snapmirror_src.$prvolume.SourceVolume) -eq $prdvolume) {
        #    Write-Log -Message "PASS : $prdvolume has a DR"
        #}
        #else {
        #    Write-Log -Message "$prdvolume has no DR" -Severity Error
        #}
        $dstvolume = $($prddb.snapmirror_src.$prvolume.DestinationVolume)
        $drvolume = $drVserver+":"+$dstvolume
        if ($dstvolume -ne $null) {
            # Compare volume state
            if($($prddb.volume.$prvolume.state) -ne $($drdb.volume.$drvolume.state)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different state than $prdVserver" -Severity Error
            }
            else { $voli++ }
            if($($prddb.volume.$prvolume.snapshot_reserved_percent) -ne $($drdb.volume.$drvolume.snapshot_reserved_percent)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different snapshot reserve than $prdVserver" -Severity Error
            }
            else { $voli++ }
            if($($prddb.volume.$prvolume.security_style) -ne $($drdb.volume.$drvolume.security_style)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different security style than $prdVserver" -Severity Error
            }
            else { $voli++ }
            #if($($prddb.volume.$prvolume.snapshot_policy) -ne $($drdb.volume.$drvolume.snapshot_policy)) {
            #    Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different snapshot policy than $prdVserver" -Severity Error
            #}
            #else { $voli++ }
            if($($prddb.volume.$prvolume.dedupe_state) -ne $($drdb.volume.$drvolume.dedupe_state)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different dedupe state than $prdVserver" -Severity Error
            }
            else { $voli++ }
            if($($prddb.volume.$prvolume.auto_delete_enabled) -ne $($drdb.volume.$drvolume.auto_delete_enabled)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different snapshot auto delete than $prdVserver" -Severity Error
            }
            else { $voli++ }
            <#
            if($($prddb.volume.$prvolume.max_autosize_mb) -ne $($drdb.volume.$drvolume.max_autosize_mb)) {
                Write-Log -Message "$($drdb.volume.$drvolume.name) on $drVserver has a different max auto size than $prdVserver" -Severity Error
            }
            else { $voli++ }
            #>
        }
        else {
            Write-Log -Message "There is no DR volume for $prdvolume on $drVserver to compare configurations" -Severity Error
        }
        if ($voli -ge 5) {
            Write-Log -Message "PASS : All comparisons passed for Volumes $prdvolume and $dstvolume" -Severity Success
        }
        }
        else {
            Write-Log -Message "There are no RW volumes on Production vserver: $prdVserver"
        }
    }
    # Compare CIFS Shares
    if ($($prddb.vserver.$prdVserver.cifs_allowed) -eq $true) {
        Write-Log -Message "*** Compare CIFS Shares"
        $pshares = $($prddb.cifs_share.keys) | ? {$_ -like "*$prdVserver*"}
        $dshares = $($drdb.cifs_share.keys) | ? {$_ -like "*$drVserver*"}
        if ($pshares.count -eq $dshares.count) {
            Write-Log -Message "PASS : $drVserver has same number of shares in $prdVserver" -Severity Success
        }
        elseif ($pshares.count -gt $dshares.count) {
            $sharediff = ($pshares.count - $dshares.count)
            Write-Log -Message "$prdVserver has : $sharediff : more shares than $drVserver" -Severity Error
        }
    }
    
    # Compare Share settings
    if ($($prddb.vserver.$prdVserver.cifs_allowed) -eq $true) {
        Write-Log -Message "*** Compare Share Settings"
        [int]$sharei = 0
        $shares = $($prddb.cifs_share.keys) | ? {$_ -like "*$prdVserver*"}
        $($prddb.cifs_share.keys) | ? {$_ -like "*$prdVserver*"} | % {
            $prshare = $_
            ($psvm , $pshare) = $prshare.split(":")
            $dbshare = $drVserver+":"+$pshare
            if (-not ([string]::IsNullOrEmpty($($drdb.cifs_share.$dbshare.name)))) {
                # Compare Share name
                if ($($prddb.cifs_share.$prshare.name) -ne $($drdb.cifs_share.$dbshare.name)) {
                    Write-Log -Message "$prdVserver share $($prddb.cifs_share.$prshare.name) name is different in $drVserver OR share $($prddb.cifs_share.$prshare.name) does not exist on $drVserver" -Severity Error
                }
                else { $sharei++ }
                # check junction path
                if ($($drdb.cifs_share.$dbshare.path) -eq $null) {
                    Write-Log -Message "$drVserver share $($drdb.cifs_share.$dbshare.name) has no junction path on $drVserver" -Severity Error
                }
                else { $sharei++ }
                # check comments
                if ($($prddb.cifs_share.$prshare.comment) -ne $($drdb.cifs_share.$dbshare.comment)) {
                    Write-Log -Message "$prdVserver share $($prddb.cifs_share.$prshare.name) comment does not match on $drVserver" -Severity Error
                }
                else { $sharei++ }
                # check share properties
                $prddbCIFSshareProps = @($($prddb.cifs_share.$prshare.share_properties).split(","))
                $drdbCIFSshareProps  = @($($drdb.cifs_share.$dbshare.share_properties).split(","))
                $sharePropComparison = (Compare-Object $prddbCIFSshareProps $drdbCIFSshareProps).InputObject
                if (($sharePropComparison).count -ne 0) {
                    Write-Log -Message "$prdVserver share $($prddb.cifs_share.$prshare.name) share properties does not match on $drVserver" -Severity Error
                }
                else { $sharei++ }
            }
            else {
                Write-Log -Message "Sharename  $pshare  does not exist on DR vserver $drVserver" -Severity Error
            }
        }
        [int]$shareSuccess = ($sharei / 4)
        if ($shareSuccess -eq $shares.count) {
            Write-Log -Message "PASS: Shared Drives on both vservers $prdVserver and $drVserver are same" -Severity Success
        }
        else {
            Write-Log -Message "Not all Shares Drives on both vservers $prdVserver and $drVserver are same" -Severity Error
        }
    }
    else {
        Write-Log -Message "*** CIFS is not enabled on Production and DR vservers: $prdVserver and $drVserver"
    }

    # Compare CIFS user-group Members
    $prdAdminstrator = $prdVserver+"\Administrator"
    if ($($prddb.vserver.$prdVserver.cifs_allowed) -eq $true) {
        Write-Log -Message "*** Compare CIFS user-group Members"
        $($prddb.local_group.$prdVserver.keys) | % {
            $localGroup = $_
            [int]$c = 0
            if (($($prddb.local_group.$prdVserver."$_") -ne $null) -and ($($drdb.local_group.$drVserver."$_") -ne $null) ) {
                foreach ($elem in $($prddb.local_group.$prdVserver."$_")) {
                    if ($elem -ne $prdAdminstrator) {
                        if ($($drdb.local_group.$drVserver."$_") -notcontains "$elem") {
                            $c++
                            Write-Log -Message "Member $elem is not part of $($localGroup) on $drVserver" -Severity Error
                        }
                    }
                }
                Write-Log -Message "{0} members were not found in $_ on $drVserver" -f $c -Severity Error
            }
        }
    }

    # Compare snapmirrors
    Write-Log -Message "*** Compare snapmirrors"
    $snapmirr = $($prddb.volume.keys) | ? {$_ -like "*$prdVserver*"}
    [int]$snapi = 0
    $($prddb.volume.keys) | ? {$_ -like "*$prdVserver*"} | % {
        $prvolume = $_
        ($prdsvm,$prdvolume) = $_.split(":")
        $dstvolume = $($prddb.snapmirror_src.$prvolume.DestinationVolume)
        # check if there is a DR volume
        if ($($drdb.snapmirror_dst.keys) -Contains $prvolume) {
            if ($($drdb.snapmirror_dst.$prvolume.IsHealthy) -ne $true) {
                Write-Log -Message "snapmirror between $prdvolume and $dstvolume is UNHEALTHY" -Severity Error
            }
            else { $snapi++ }
        }
        else {
            Write-Log -Message "$prdvolume has no DR" -Severity Error
        }
   }
   if ($snapi -eq $snapmirr.count) {
        Write-Log -Message "All snapmirror relations between $prdVserver and $drVserver are healthy" -Severity Success
   }
  
   # Compare Data Lifs
   Write-Log -Message "*** Compare Data Lifs"
   $prdDataLif = $($prddb.vserver_dataLif.keys) | ? {($_ -like "*$prdVserver*")}
   $drDataLif  = $($drdb.vserver_dataLif.keys) | ? {($_ -like "*$drVserver*")}
   [int]$lifi = 0
   if (($prdDataLif -ne $null) -and ($drDataLif -ne $null)) {
        # check role
        if ($($prddb.vserver_dataLif.$prdDataLif.role) -ne $($drdb.vserver_dataLif.$drDataLif.role)) {
            Write-Log -Message "Data LIF : $drDataLif : role do not match to vservers $prdVserver lif : $prdDataLif :" -Severity Error
        }
        else { $lifi++ }
        # check status
        if ($($prddb.vserver_dataLif.$prdDataLif.status) -ne $($drdb.vserver_dataLif.$drDataLif.status)) {
            Write-Log -Message "Data LIF : $drDataLif : status do not match to vservers $prdVserver lif : $prdDataLif :" -Severity Error
        }
        else { $lifi++ }
        # check protocols
        if ($($prddb.vserver_dataLif.$prdDataLif.protocols) -ne $($drdb.vserver_dataLif.$drDataLif.protocols)) {
            Write-Log -Message "Data LIF : $drDataLif : protocols do not match to vservers $prdVserver lif : $prdDataLif :" -Severity Error
        }
        else { $lifi++ }
   }
   else {
        Write-Log -Message "Data lif is missing on $drVserver" -Severity Error
   }
   if ($lifi -ge 3) {
        Write-Log -Message "PASS : Data Lifs on vservers $prdVserver and $drVserver passed all comparisons" -Severity Success
   }

   # Compare Anti-Virus Lifs
   if ($($prddb.vserver.$prdVserver.cifs_allowed) -eq $true) {
       Write-Log -Message "*** Compare Anti-Virus Lifs"
       $prdavLif = $($prddb.vserver_avLif.keys) | ? {($_ -like "*$prdVserver*")}
       $dravLif  = $($drdb.vserver_avLif.keys) | ? {($_ -like "*$drVserver*")}
       [int]$avlifi = 0
       if (($prdavLif -ne $null) -and ($dravLif -ne $null)) {
            # check role is same
            if ($($prddb.vserver_avLif.$prdavLif.role) -ne $($drdb.vserver_avLif.$dravLif.role)) {
                Write-Log -Message "Anti-Virus LIF : $dravLif : role do not match to vservers $prdVserver lif : $prdavLif :" -Severity Error
            }
            else { $avlifi++ }
            if ($($prddb.vserver_avLif.$prdavLif.status) -ne $($drdb.vserver_avLif.$dravLif.status)) {
                Write-Log -Message "Anti-Virus LIF : $dravLif : status do not match to vservers $prdVserver lif : $prdavLif :" -Severity Error
            }
            else { $avlifi++ }
            if ($($prddb.vserver_avLif.$prdavLif.protocols) -ne $($drdb.vserver_avLif.$dravLif.protocols)) {
                Write-Log -Message "Anti-Virus LIF : $dravLif : protocols do not match to vservers $prdVserver lif : $prdavLif :" -Severity Error
            }
            else { $avlifi++ }
       }
       else {
            Write-Log -Message "Anti-Virus lif is missing on $drVserver" -Severity Error
       }
       if ($avlifi -ge 3) {
            Write-Log -Message "PASS : Anti-Virus Lifs on vservers $prdVserver and $drVserver passed all comparisons" -Severity Success
       }
   }

}
Write-Log -Message "================================================"

Start-Sleep -Seconds 5

if (Test-Path $scriptLogPath) {
$Header = @"
    <style>
    body {background-color:Ivory; font-family:Tahoma; font-size:12pt;}
    td, th {border:1px solid black; border-collapse:collapse;}
    th {color:white; background-color:Blue;}
    table, tr, td, th {padding: 2px; margin: 0px}
    table {margin-left:70px;}
    </style>
"@

## put the csvline info gathering code here
$csvlines = import-csv -Delimiter "," -Path $scriptLogPath
##

## create a TABLE from the gathered info
$strTableStartHTML = "<TABLE CELLSPACING=1 CELLPADDING=1 BORDER=1>`n<TR><TH>Severity</TH><TH>Message</TH></TR>"
$strTableBodyHTML = foreach ($csvline in $csvlines) {
    ## create the row STYLE HTML based on this csvline's PercentFree value
    $strRowStyleHTML = if ($csvline.Severity -eq "Error") 
                            {" STYLE='color: Red'"} 
                       elseif ($csvline.Message -eq "================================================") 
                            {" STYLE='color:white; background-color:white'"}
                       elseif ($csvline.Message -like "*Compare vservers*") 
                            {" STYLE='color:white; background-color:Blue'"}
                       elseif ($csvline.Message -like "*Comparing vservers on clusters*") 
                            {" STYLE='color:white; background-color:Blue'"}
                       elseif ($csvline.Message -match "\*+") 
                            {" STYLE='font-weight: bold'"}
                       else {$null}
    ## return the HTML for the row for this csvline
    "<TR$strRowStyleHTML><TD>$($csvline.Severity)</TD><TD>$($csvline.Message)</TD></TR>`n"
} ## end foreach
$strTableEndHTML = "</TABLE>"

ConvertTo-Html -Title "DR Validation Info" -Body $Header$strTableStartHTML$strTableBodyHTML$strTableEndHTML | Out-File $scriptHTMLLogPath

Start-Sleep -Seconds 2

if (Test-Path $scriptHTMLLogPath) {
    # SEND EMAIL MESSAGE
    [string]$mailbody       = (Get-Content -Raw -Path $scriptHTMLLogPath)
    [string[]]$recipients  = "nitish.chopra@lab.local"
    $splat = @{
        'to' = $recipients;
        'subject' = "DR Validation Info : $pcluster and $dcluster ";
        'SmtpServer' = "appsmtp.lab.local";
        'from' = "Automated_Reports@lab.local";
        'body' = $mailbody;
        'BodyAsHtml' = $true;
    }
    Send-MailMessage @splat
   }
   else {Write-Host "HTML  file does not exist"}
}
else {
    Write-Host "csv file does not exist"
}