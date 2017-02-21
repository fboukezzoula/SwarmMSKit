Set-StrictMode -version 3
$ErrorActionPreference = "Stop"

<# SwarmMSKit v1.0.0.2

Author : Fouzi BOUKEZZOULA

Twitter, Facebook : @fboukezzoula

https://github.com/fboukezzoula/SwarmMSKit

@January 2017

--------------------------------------------------------------------------------------------------------------------------------------------------

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

[System.Text.Encoding]::GetEncoding(437) | Out-Null

#region Constants/Varibales
### -----------------------------------
###       Constants/Varibales
### -----------------------------------

$global:WorkDir                               = "C:\SwarmMSKit"
$global:VMPath                                = "$global:WorkDir\VHD_Files"
$global:Model_NanoServerDataCenter            = "$global:WorkDir\VHD_Reference\NanoServerDataCenter.vhd"

$global:LogDismTimestamp                      = (Get-Date -Format u).Replace("-","_").Replace(" ","_").Replace(":","").Replace("Z","")

<#
We have to create an virtual internal network switch on Hyper-V. The name of this Virtual Switch is InternalNetwork in this case
We have set a static IP on this virtual NIC use for this internal network
The DNS and AD will be use this static @IP and this virtual vlan

Then we set the desire >> first @IP << of our Nanoserver VM of this subnet; which will be the first VM of our Cluster Swarm 
In this case, the first NanoServer VM of our Cluster Swarm will have this @IP 10.1.0.24
#>

$global:IPAddress               = "10.1.0.24"
$global:GatewayAddress          = "10.1.0.1"
$global:SubnetMask              = "255.255.255.0"
$global:DNSAddresses            = "10.1.0.1"

$global:Subnet                  = "10.1.0."
$global:VMSwitch                = "InternalNetwork"

# System Configuration for our NanoServer VM, 2 vCPU and 2 Go Ram
$global:VMProcessor             = 4
$global:VMRam                   = 2048MB

# Type Of Authentication to the NanoServer : Local Account (default value: Local) or AD Account (AD) ?
$global:AuthenticationType = "AD"

# Prefix of your VM Nanoserver in Hyper-V and for the hostname, if "Nano-" > Nano-Manager-01, Nano-Worker-01, etc ....
$global:ContainerHostName = "Nano-"

#How many Members/VM NanoServer will be deploy in your Cluster Swarm ?
$global:ServersInCluster   = 3

# Our dedicated TCP POrt for our Cluster Swarm Service
$global:SwarmClusterPort = "2017"

# Set firewall rules for all our Cluster : Docker daemon, swarm, consul, veualt, registry, file sharing, winrm, etc ...
# if $True  = set each FW rule
# if $False = we disable the Microsoft Firewall so all the ports ar open inbound/outbound
$Firewall = $True

$LastOctetAdress = $IPAddress.Split('.')
$NextIP = [int]($LastOctetAdress[-1]) 

$global:InterfaceNameOrIndex = (Get-NetAdapter | Where-Object {$_.Name -eq "vEthernet ($global:VMSwitch)"}).ifIndex

$global:ClusterMembers = [System.Collections.ArrayList]@("$IPAddress")
$global:ContainerIPAdress = [System.Collections.ArrayList]@("")
#endregion


Import-Module $WorkDir\SwarmMSKit -Force -Verbose

#region ServersConfigurationCluster
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
#endregion

#region ClusterNodeCreation
Function global:ClusterNodeCreation {

    param([bool]$IsSwarmManager,[String]$ContainerHostNameNodeCreate, [String]$ContainerIPNodeCreate, [String]$BootstrapExpectServers)
    
    $global:ContainerIPAdress[0]="$ContainerIPNodeCreate"   
       
    $ClusterMembers.Add("$ContainerIPNodeCreate") | Out-Null

    if(Test-Path -Path $global:VMPath\$ContainerHostNameNodeCreate.vhd) {
        Remove-Item -Path $global:VMPath\$ContainerHostNameNodeCreate.vhd -Force  
    }

    "Cloning the VHD NanoServerDataCenter reference built image and renaming the VHD image with the target NanoServer Name : $ContainerHostNameNodeCreate.vhd ... Please Wait ..."
    Copy-Item -Path $global:Model_NanoServerDataCenter -Destination $global:VMPath\$ContainerHostNameNodeCreate.vhd 
    " "
    PurgeTempMountFolder "$global:VMPath\nanoserver-offine-temp" 
    PurgeTempMountFolder "$global:VMPath\Logs" 
      
    New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp" -Force | Out-Null   
    New-Item -Type Directory -Path "$global:VMPath\Logs" -Force | Out-Null   
    New-Item -Type Directory -Path "$global:VMPath\Logs\$global:LogDismTimestamp" -Force | Out-Null 
    
    $MountImage="Dism /Mount-Image /ImageFile:$global:VMPath\$ContainerHostNameNodeCreate.vhd /index:1 /MountDir:$global:VMPath\nanoserver-offine-temp /LogLevel:3 /LogPath:$global:VMPath\Logs\$global:LogDismTimestamp\dism.log /Quiet"
    $MountImage
    " "
    Invoke-Expression $MountImage | Out-Host | Out-Null 
        
    New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp\Windows\Setup\Scripts" -Force | Out-Null 

#region AuthenticationType
    if ($AuthenticationType -eq "Local") {

            "Using a Local account  ... Injection this credential to the target NanoServer Name : $ContainerHostNameNodeCreate.vhd ... Please Wait ... "
            " "
            # Local Credential which will be the admin NanoServer account
            $global:Username              = "Administrator"
            $global:clearadminPassword    = "ertyui"

            $global:adminPassword  = ConvertTo-SecureString $clearadminPassword -AsPlainText -Force
            $global:Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username,$adminPassword  

$unattend = @"
<?xml version='1.0' encoding='utf-8'?>  
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

<settings pass="offlineServicing">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <ComputerName>$ContainerHostNameNodeCreate</ComputerName>
</component>
</settings>

<settings pass="oobeSystem">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <UserAccounts>
    <AdministratorPassword>
        <Value>$global:clearadminPassword</Value>
        <PlainText>true</PlainText>
    </AdministratorPassword>
    </UserAccounts>
      
</component>
</settings>

<settings pass="specialize">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <RegisteredOwner>Fouzi BOUKEZZOULA</RegisteredOwner>
    <RegisteredOrganization>SwarmMSKit</RegisteredOrganization>
</component>
</settings>
</unattend> 
"@

        $unattend > "$WorkDir\unattend.xml"

        (Get-Content -path "$WorkDir\unattend.xml" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$WorkDir\unattend.xml"

        New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp\Windows\panther" -Force | Out-Null

        $Command_Inject_unattend = "dism.exe /Image:'$global:VMPath\nanoserver-offine-temp' /Apply-Unattend:'$WorkDir\unattend.xml'"
        $Command_Inject_unattend

        Invoke-Expression $Command_Inject_unattend 

        copy $WorkDir\unattend.xml $global:VMPath\nanoserver-offine-temp\Windows\panther
           
        
        } else {

            "Using a Domain Active Directory account ... Injection this credential to the target NanoServer Name : $ContainerHostNameNodeCreate.vhd ... Please Wait ..."
            " "

            # AD Credential which will be the admin NanoServer account
            $global:Username              = "FBOUKEZZOULA\Administrateur"
            $global:clearadminPassword    = "YourPassAD"
            $global:DomainName            = "FBOUKEZZOULA"
            $global:adminPassword  = ConvertTo-SecureString $clearadminPassword -AsPlainText -Force

            $global:Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username,$adminPassword

            
            $global:DomainBlobPath = "$WorkDir\DJOIN_$ContainerHostNameNodeCreate.TXT"
            # we integrated/join automatically the NanoServer VM in an Active Directory Domain with the DJOIN command and use the blob file during the Nanoserver installation
            $Command_Join = "DJOIN /provision /domain $DomainName /machine $ContainerHostNameNodeCreate /REUSE /savefile $DomainBlobPath"
            $Command_Join
            " "
            Invoke-Expression $Command_Join

            $Command_Inject_Join = "djoin /RequestODJ /LoadFile '$DomainBlobPath' /WindowsPath '$global:VMPath\nanoserver-offine-temp\Windows' 2>&1"
            $Command_Inject_Join 
            " "

            Invoke-Expression $Command_Inject_Join          
                       
    } 


    " "
    $CommitImage="Dism /Commit-Image /MountDir:$global:VMPath\nanoserver-offine-temp /LogLevel:3 /LogPath:$global:VMPath\Logs\$global:LogDismTimestamp\dism.log /Quiet"
    $CommitImage
    " "
    Invoke-Expression $CommitImage | Out-Host | Out-Null 

    $UnmountImage="Dism /Unmount-Image /MountDir:$global:VMPath\nanoserver-offine-temp /commit /LogLevel:3 /LogPath:$global:VMPath\Logs\$global:LogDismTimestamp\dism.log /Quiet" 
    $UnmountImage
    " "
    Invoke-Expression $UnmountImage | Out-Host | Out-Null 
       

    "Create, Set vCPU and RAM, Enabled the VM according your configuration and start the VM Name $ContainerHostNameNodeCreate in the Hyper-V ... Please Wait ..."
    " "  
    Create-Set-VM-Hyper-V $global:VMSwitch $global:VMPath $ContainerHostNameNodeCreate $global:VMProcessor $global:VMRam | Out-Host | Out-Null 
     
    "Get-VMNetworkAdapter -VMName $ContainerHostNameNodeCreate  | Set-VMNetworkConfiguration -IPAddress $ContainerIPNodeCreate -Subnet $SubnetMask -DNSServer $DNSAddresses -DefaultGateway $GatewayAddress"
    Get-VMNetworkAdapter -VMName $ContainerHostNameNodeCreate  | Set-VMNetworkConfiguration -IPAddress $ContainerIPNodeCreate -Subnet $SubnetMask -DNSServer $DNSAddresses -DefaultGateway $GatewayAddress
    Enabled-VM-Hyper-V $ContainerHostNameNodeCreate  | Out-Host | Out-Null 

    Start-VM -Name $ContainerHostNameNodeCreate    
        
    Pause 30 $ContainerHostNameNodeCreate | Out-Host | Out-Null

    Wait-WinRM-Reachable $ContainerIPNodeCreate

    # Prepare the VM NanoServer: with ou without Firewall, Regional Settings, etc ... if first Argument = $True, we set all the FW rules; if $False, we disable the FW MS service (no secured)
    Invoke-Command -ComputerName $ContainerIPNodeCreate -Credential $global:Cred -ScriptBlock ${function:NanoSetup} -ArgumentList $global:Firewall, $global:SwarmClusterPort | Out-Host | Out-Null
       
    Pause 30 $ContainerHostNameNodeCreate | Out-Host | Out-Null

    Wait-WinRM-Reachable $ContainerIPNodeCreate
           
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
#endregion

#region CreateServerNode
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
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            $Message = "Starting Creation SwarmManager/Consul Server : "+$ContainerHostName+"Manager-0"+$TotalSwarmManager+ "   [@IP :" +$IPAdressClusterSwarmManager +"]"   
            $Message 
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            " " 

            $ContainerHostNameNodeCreate = $ContainerHostName+"Manager-0"+$TotalSwarmManager

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
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" 
            $Message = "Starting Creation SwarmWorker/Consul Agent     : " +$ContainerHostName+"Worker-0"+$TotalSwarmNodes+ "   [@IP :" +$IPAdressClusterSwarmNode +"]" 
            $Message
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" 
            " " 

            $ContainerHostNameNodeCreate = $ContainerHostName+"Worker-0"+$TotalSwarmNodes

            ClusterNodeCreation $False $ContainerHostNameNodeCreate $IPAdressClusterSwarmNode $NbrSwarmManager

            $TotalSwarmNodes++
            $TotalServers++

        } While ($TotalSwarmNodes -le $NbrSwarmNode)

    } while ($TotalServers -le $ServersInCluster)

}
#endregion


## MAIN PROGRAMM
clear;

Write-Host "Start at : $(Get-Date -format t)"  
$Start = (Get-Date).Minute
" "

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

Invoke-Command -ComputerName $ClusterMembers[0] -Credential $global:Cred -ScriptBlock ${function:VaultServer-PrivateRegistry-UCP} -ArgumentList $ClusterMembers[0], $global:SwarmClusterPort | Out-Host | Out-Null

# Finally, after building the portainer.cmd we launch the UCP IHM/GUI on the first member of the cluster which is a swarm manager, a consul server and a vault server
$PSCommand = "c:\portainer\portainer.cmd"
Invoke-Command -ScriptBlock {param($command) cmd /c $command} -args $PSCommand -ComputerName $ClusterMembers[0] -Credential $global:Cred -AsJob 

" "
" "
Write-Host "End at : $(Get-Date -format t)"
$End = (Get-Date).Minute
" "
" "
" "
"**********************************************************************************************************"
" "
" "
"      Full Processing time for deploying your Cluster Swarm with all dependencies and tools   :"
" "
" "
"                                      $($End-$Start) Minutes"


