# SwarmMSKit v1.0.0.0 
# Author : Fouzi BOUKEZZOULA
#
# GitHub, Twitter, Facebook : @fboukezzoula
#
# January 2017

clear;

<#
Execution PS Security has to be set like for example : 

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force 
or 
Set-ExecutionPolicy Unrestricted

For having a good output console for the special (French) characters, execute these commands on the PS Prompt before executing this ps1 programm
$ConsoleCommand ="[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(437)"
Invoke-Expression $ConsoleCommand

To connect to our new NanoServer VM with WinRM protocol :

Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service winrm
#>

### -----------------------------------
###       Constants/Varibales
### -----------------------------------

$global:WorkDir              = "C:\SwarmMSKit"
$global:VMPath               = "$global:WorkDir\VHD_Files"
$global:MediaPath            = "$global:WorkDir\W2K16"
$global:ToolsSource          = "$global:WorkDir\ToolsSource"
$global:ServicingPackages    = "$global:WorkDir\ServicingPackages"

<#
We have to create an virtuak internal network switch on Hyper-V. The name of this Virtual Switch is InternalNetwork in this case
We have set a static IP on this virtual NIC use for this internal network
The DNS and AD will be use this static @IP and this virtual vlan

Then we set the desire >> first @IP << of our Nanoserver VM of this subnet; which will be the first VM of our Cluster Swarm 
In this case, the first NanoServer VM odf our Cluster Swarm will have this @IP 10.1.0.24
#>

$global:IPAddress      = "10.1.0.24"
$global:GatewayAddress = "10.1.0.1"
$global:SubnetMask     = "255.255.255.0"
$global:DNSAddresses   = "10.1.0.1"


$global:Subnet         = "10.1.0."
$global:VMSwitch       = "InternalNetwork"

# System Configuration for our NanoServer VM, 2 vCPU and 2 Go Ram
$global:VMProcessor           = 2
$global:VMRam                 = 2048MB

# AD Credential which will be the admin NanoServer account
$global:Username              = "FBOUKEZZOULA\Administrateur"
$global:clearadminPassword    = "24WhNone09"

$global:DomainName            = "FBOUKEZZOULA"

$global:adminPassword  = ConvertTo-SecureString $clearadminPassword -AsPlainText -Force

$global:Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username,$adminPassword

$global:ContainerHostName = "Nano-"

$global:ServersInCluster   = 3

# Our dedicated TCP POrt for our Cluster Swarm Service
$global:SwarmClusterPort = "2017"

$LastOctetAdress = $IPAddress.Split('.')
$NextIP = [int]($LastOctetAdress[-1]) 

$global:ClusterMembers = [System.Collections.ArrayList]@("$IPAddress")
$global:ContainerIPAdress = [System.Collections.ArrayList]@("")

Import-Module $WorkDir\SwarmMSKit -Force -Verbose
Import-Module $WorkDir\NanoServerImageGenerator -Force -Verbose

Function global:ServersConfigurationCluster {

param ($NbrSwarmManager,$NbrConsulServer,$NbrSwarmNode,$NbrConsulAgent)

if ($NbrSwarmManager -gt 1) {
$NbreSwarmManagerNodes ="*                      $NbrSwarmManager Swarm Managers   -   $NbrConsulServer Consul Servers                            *"
} elseif ($NbrSwarmManager -eq 1) {
$NbreSwarmManagerNodes ="*                      $NbrSwarmManager Swarm Manager   -    $NbrConsulServer Consul Server                             *"
}

$myCluster = @" 

*******************************************************************************************
*              The configuration of your Cluster Swarm  will be :                         *
*                                                                                         *
*                                                                                         *
$NbreSwarmManagerNodes
*                      $NbrSwarmNode Swarm Workers   -    $NbrConsulAgent Consul Agents                             *
*                                                                                         *
*                                                                                         *
*                  And 1 Vault Server for all your Cluster Swarm                          *
*******************************************************************************************

"@

$myCluster 

}

Function global:ClusterNodeCreation {

    param([bool]$IsSwarmManager,[String]$ContainerHostNameNodeCreate, [String]$ContainerIPNodeCreate, [String]$BootstrapExpectServers)

    $global:ContainerIPAdress[0]="$ContainerIPNodeCreate"   
    
    NewNanoServerImage-Domain $global:ServicingPackages $global:VMPath $global:WorkDir $global:adminPassword $global:MediaPath $ContainerHostNameNodeCreate $ContainerIPNodeCreate $global:GatewayAddress $global:SubnetMask $global:DNSAddresses $global:DomainName | Out-Host | Out-Null
       
    Create-Set-VM-Hyper-V $global:VMSwitch $global:VMPath $ContainerHostNameNodeCreate $global:VMProcessor $global:VMRam | Out-Host | Out-Null
    Enabled-Start-VM-Hyper-V $ContainerHostNameNodeCreate  | Out-Host | Out-Null 

    Pause 30 $ContainerHostNameNodeCreate | Out-Host | Out-Null

    Wait-WinRM-Reachable $ContainerIPNodeCreate | Out-Host | Out-Null
    
    $ClusterMembers.Add("$ContainerIPNodeCreate") | Out-Null

     if ($IsSwarmManager -eq "$True") {
        
        # If Swarm Manager/Consul Server Node 
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:DockerInstallation} -ArgumentList $True, $ClusterMembers[0]  | Out-Host | Out-Null        
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:ConsulServer} -ArgumentList $ContainerIPNodeCreate, $ClusterMembers[0], $BootstrapExpectServers | Out-Host | Out-Null
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:SwarmManager} -ArgumentList $ContainerIPNodeCreate, $ClusterMembers[0], $global:SwarmClusterPort | Out-Host | Out-Null
        } 
    else {
        # If Swarm Node/Consul Agent Node :
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:DockerInstallation} -ArgumentList $False, $ClusterMembers[0] | Out-Host | Out-Null
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:ConsulAgent} -ArgumentList $ContainerIPNodeCreate, $ClusterMembers[0] | Out-Host | Out-Null
        Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:SwarmWorker} -ArgumentList $ContainerIPNodeCreate, $ClusterMembers[0], $global:SwarmClusterPort | Out-Host | Out-Null
    }
}

Function global:CreateServerNode {

    param($ServersInCluster,$ContainerHostName,$NextIP,$NbrSwarmManager,$NbrSwarmNode)
    
    $TotalServers = 1

    Do
    {

    ### Create the SwarmManager Node(s) and Consul Server(s) Node(s)
    $TotalSwarmManager = 1 

        Do
        {
        
            $NextIP = [int]($LastOctetAdress[-1]) + $TotalSwarmManager
            $Base = $NextIP-1

            $IPAdressClusterSwarmManager = "$Subnet$Base"

            " " 
            $Message = "Starting Creation SwarmManager/Consul Server : "+$ContainerHostName+"Manager-"+$TotalSwarmManager+ "   [@IP :" +$IPAdressClusterSwarmManager +"]"   
            $Message 
            " " 

            $ContainerHostNameNodeCreate = $ContainerHostName+"Manager-"+$TotalSwarmManager

            ClusterNodeCreation $True $ContainerHostNameNodeCreate $IPAdressClusterSwarmManager $NbrSwarmManager 

            $TotalSwarmManager++
            $TotalServers++
  

        } While ($TotalSwarmManager -le $NbrSwarmManager)

    ### Create the SwarwWorker(s) and Consul Agents(s) Node(s)
    $TotalSwarmNodes  = 1 
        Do
        {
            $NextIP = [int]($LastOctetAdress[-1]) + $TotalServers
            $Base = $NextIP-1
            $IPAdressClusterSwarmNode = "$Subnet$Base"

            " " 
            $Message = "Starting Creation SwarmWorker/Consul Agent     : " +$ContainerHostName+"Worker-"+$TotalSwarmNodes+ "   [@IP :" +$IPAdressClusterSwarmNode +"]" 
            $Message 
            " " 

            $ContainerHostNameNodeCreate = $ContainerHostName+"Worker-"+$TotalSwarmNodes

            ClusterNodeCreation $False $ContainerHostNameNodeCreate $IPAdressClusterSwarmNode $NbrSwarmManager

            $TotalSwarmNodes++
            $TotalServers++

        } While ($TotalSwarmNodes -le $NbrSwarmNode)

    } while ($TotalServers -le $ServersInCluster)

}

## MAIN PROGRAMM

if ($ServersInCluster -lt 3) {
    Write-Host " ";Write-host "For creating a cluster Swarm with this programm, you need miminum 3 VMs. Please choose a correct number of Servers and retry ..."  ;
    Write-Host " "; break
} 
# If ServersInCluster (>= 3  and < 5) (=3,4)
elseif (($ServersInCluster -ge 3) -and ($ServersInCluster -lt 5)) {

    $NbrSwarmManager = $NbrConsulServer = 1
    $NbrSwarmNode    = $NbrConsulAgent  = ([int]($ServersInCluster)-1)
}
# If ServersInCluster (>= 5 and < 8)
elseif (($ServersInCluster -ge 5) -and ($ServersInCluster -lt 8)) {

    $NbrSwarmManager = $NbrConsulServer = 2
    $NbrSwarmNode    = $NbrConsulAgent  = ([int]($ServersInCluster)-2)
}
# If ServersInCluster (>= 8) 
elseif ($ServersInCluster -ge 8) {

    $NbrSwarmManager = $NbrConsulServer = 3
    $NbrSwarmNode    = $NbrConsulAgent  = ([int]($ServersInCluster)-3)
}

# Let's Go !

ServersConfigurationCluster $NbrSwarmManager $NbrConsulServer $NbrSwarmNode $NbrConsulAgent 

CreateServerNode $ServersInCluster $ContainerHostName $NextIP $NbrSwarmManager $NbrSwarmNode | Out-Host | Out-Null 

Invoke-Command -ComputerName $ClusterMembers[0] -Credential $global:Cred -ScriptBlock ${function:VaultServer} -ArgumentList $ClusterMembers[0] | Out-Host | Out-Null 

SwarmMSKit-Private-Registry $global:ToolsSource $global:Username $global:clearadminPassword $ClusterMembers[0] | Out-Host | Out-Null