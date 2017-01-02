# SwarmMSKit

1. [Overview](#overview)

2. [SwarmMSKit Description - What the module does and why it is useful](#SwarmMSKit-description)
3. [Setup - The basics of getting started with SwarmMSKit]
    * [Setup requirements](#setup-requirements)
    * [Beginning with SwarmMSKit](#beginning-SwarmMSKit)
4. [Usage - SwarmMSKit](#usage)
5. [Video Tutorial](#youtube channel)

overview
-----

Provisioning a Full MS NanoServer Cluster Swarm on Hyper-V + Consul + Vault + Private Registry ... all integrated in an Active Directory Domain and all the VM NanoServer on Hyper-V 

SwarmMSKit-description
-----

Provisioning a Full MS NanoServer Cluster Swarm on Hyper-V with Consul Hashicorp software as Discovery Service, Vault Hashicorp software as a Secret Management Store and a Private Docker Registry host on Nexus OSS software.
All VMs are integrated in an Active Directory Domain and all the VM NanoServer will running on Hyper-V.

We use the latest Docker Daemon Engine, Vault, Consul and Nexus OSS versions.
 
The Windows Server 2016 has to be updated with the latest KB/Hotfixs.

For the NanoServer VHD, we will install these KB/Hotfixes too.


setup-requirements
-----

Windows 10 Pro or Entreprise Version (need Hyper-V)
Windows Server 2016 Standard or Datacenter 

beginning-SwarmMSKit
-----

Set constants/variables in the SwarmMSKitProvisioning.ps1 file :

* WorkDir              = "C:\SwarmMSKit"
* VMPath               = "$global:WorkDir\VHD_Files"
* MediaPath            = "$global:WorkDir\W2K16"
* ToolsSource          = "$global:WorkDir\ToolsSource"
* ServicingPackages    = "$global:WorkDir\ServicingPackages"


IP Configuration of your first VM NanoServer and VM Switch Hyper-V configuration :

* IPAddress      = "10.1.0.24"
* GatewayAddress = "10.1.0.1"
* SubnetMask     = "255.255.255.0"
* DNSAddresses   = "10.1.0.1"
* Subnet         = "10.1.0."
* VMSwitch       = "InternalNetwork"

System Configuration for our NanoServer VM, 2 vCPU and 2 Go Ram
* VMProcessor           = 2
* VMRam                 = 2048MB

AD Credential which will be the admin NanoServer account
* Username              = "FBOUKEZZOULA\Administrateur"
* clearadminPassword    = "YourPassWord"
* DomainName            = "FBOUKEZZOULA"

Name (Netbios/Hostname of the NanoServer and AD coputer Names; Name in Hyper-V)
* ContainerHostName = "Nano-"

Number of tour Cluster Swarm members 
* ServersInCluster   = 3

Our dedicated TCP POrt for our Cluster Swarm Service
* SwarmClusterPort = "2017"


usage
-----

* Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force 
or 
* Set-ExecutionPolicy Unrestricted

To connect to our new NanoServer VM with WinRM protocol :

* Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
* Restart-Service winrm

Then run the SwarmMSKitProvisioning.ps1 file ...


When it's finish ...

* set DOCKER_HOST=tcp://@YourFirstIP:@YourClusterSwarmPort

examples :

* set DOCKER_HOST=tcp://10.1.0.24:2017

* docker images

* docker run -it nanoserver powershell
* docker run -it nanoserver cmd

* docker login -u admin -p admin123 @YourFirstIP:8123
* docker push nanoserver

youtube channel
-----

Stay tunned, very soon ...

















