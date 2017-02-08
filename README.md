![ScreenShot](https://raw.githubusercontent.com/fboukezzoula/SwarmMSKit/master/pics/logoSwarmMSKit.png)


# SwarmMSKit

1. [Overview](#SwarmMSKit-Overview)

2. [SwarmMSKit Description - What the tool does and why it is useful](#SwarmMSKit-Description)
3. [Setup - The basics of getting started with SwarmMSKit]
    * [Setup requirements](#SwarmMSKit-Setup-requirements)
    * [Beginning with SwarmMSKit](#SwarmMSKit-Beginning)
4. [Usage - SwarmMSKit](#SwarmMSKit-Usage)
5. [Video Tutorial](#SwarmMSKit-Youtube channel)

SwarmMSKit-Overview
-----

Provisioning a Full MS NanoServer Cluster Swarm on Hyper-V + Consul + Vault + Private Registry + Management UI for your cluster ... all the VMs can be integrated in an Active Directory Domain or you can use a Local account. 


SwarmMSKit-Description
-----

Provisioning a Full MS NanoServer Cluster Swarm on Hyper-V with Consul Hashicorp software as Discovery Service, Vault Hashicorp software as a Secret Management Store and a Private Docker Registry host on Nexus OSS software.

All VMs can be integrated in an Active Directory Domain during the provisioning or you can use a local windows account.

All the VM NanoServer will running on Hyper-V.

All the VMs NanoServer will be up to date (latest KBs/Hotfixs) and will hosted the last docker OSImage nanoserver (microsoft/nanoserver, nanoserver tagged). 

You can disable the Microsoft Firewall or use the Firewall : the SwarmMSKit will create for you all the firewall rules (more than 16 rules) for enabled the access to the Docker Daemon, Swarm, Consul, Vault, Private Registry, Management UI, WinRM, File Sharing, etc ....

We use the latest supported Docker Daemon Engine, launched this last 18 January 2017 (1.13), Swarm (1.2.6 : build the swarm.exe file with the official Docker Swarm GitHub source), Vault (0.6.4), Consul (0.7.2) and Nexus OSS (3.2.0-01) versions.

Notice that I've built locally the swarm.exe binary with the latest version of this docker/swarm source codes :
https://github.com/docker/swarm/releases/tag/v1.2.6


######docker -H tcp://10.1.0.24:2375 version :
	Client:
	 Version:      1.13.0
	 API version:  1.25
	 Go version:   go1.7.3
	 Git commit:   49bf474
	 Built:        Wed Jan 18 16:20:26 2017
	 OS/Arch:      windows/amd64

	Server:
	 Version:      1.13.0
	 API version:  1.25 (minimum version 1.24)
	 Go version:   go1.7.3
	 Git commit:   49bf474
	 Built:        Wed Jan 18 16:20:26 2017
	 OS/Arch:      windows/amd64
	 Experimental: false
 

######docker -H tcp://10.1.0.24:2017 info
	Containers: 0
	 Running: 0
	 Paused: 0
	 Stopped: 0
	Images: 2
	Server Version: swarm/1.2.6
	Role: primary
	Strategy: spread
	Filters: health, port, containerslots, dependency, affinity, constraint, whitelist
	Nodes: 2
	 Nano-Worker-01: 10.1.0.25:2375
	  └ ID: 6WOI:CJAO:QPL2:D7ID:XD4M:RAQ3:O4AM:374O:GEC6:V2FW:YYUX:APNF
	  └ Status: Healthy
	  └ Containers: 0 (0 Running, 0 Paused, 0 Stopped)
	  └ Reserved CPUs: 0 / 4
	  └ Reserved Memory: 0 B / 2.1 GiB
	  └ Labels: kernelversion=10.0 14393 (14393.206.amd64fre.rs1_release.160915-0644), operatingsystem=Windows Server 2016 Datacenter, storagedriver=windowsfilter
	  └ UpdatedAt: 2017-02-08T15:51:52Z
	  └ ServerVersion: 1.13.0
	 Nano-Worker-02: 10.1.0.26:2375
	  └ ID: JVFE:5MS7:XRWC:OQA4:2QZJ:LUBA:GRIJ:AHRX:5SM7:YA25:LXGC:VLXK
	  └ Status: Healthy
	  └ Containers: 0 (0 Running, 0 Paused, 0 Stopped)
	  └ Reserved CPUs: 0 / 4
	  └ Reserved Memory: 0 B / 2.1 GiB
	  └ Labels: kernelversion=10.0 14393 (14393.206.amd64fre.rs1_release.160915-0644), operatingsystem=Windows Server 2016 Datacenter, storagedriver=windowsfilter
	  └ UpdatedAt: 2017-02-08T15:51:44Z
	  └ ServerVersion: 1.13.0
	Plugins:
	 Volume:
	 Network:
	Swarm:
	 NodeID:
	 Is Manager: false
	 Node Address:
	Kernel Version: 10.0 14393 (14393.206.amd64fre.rs1_release.160915-0644)
	Operating System: windows
	Architecture: amd64
	CPUs: 8
	Total Memory: 4.199 GiB
	Name: Nano-Manager-01
	Docker Root Dir:
	Debug Mode (client): false
	Debug Mode (server): false
	WARNING: No kernel memory limit support
	Experimental: false
	Live Restore Enabled: false

######vault status -address=http://10.1.0.24:8200
	Sealed: false
	Key Shares: 5
	Key Threshold: 3
	Unseal Progress: 0
	Version: 0.6.4
	Cluster Name: vault-cluster-80d388b2
	Cluster ID: 43494c69-f954-aab3-47d1-6663bc1c6c1f

	High-Availability Enabled: true
		Mode: active
		Leader: http://10.1.0.24:8200
	
 
######consul members --rpc-addr=10.1.0.24:8400
	Node             Address         Status  Type    Build  Protocol  DC
	Nano-Manager-01  10.1.0.24:8301  alive   server  0.7.2  2         nano-swarm
	Nano-Worker-01   10.1.0.25:8301  alive   client  0.7.2  2         nano-swarm
	Nano-Worker-02   10.1.0.26:8301  alive   client  0.7.2  2         nano-swarm
 

For the NanoServer VHD reference, we will use the latest and official Microsoft Nanoserver VHD :
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016

(you have to SignIn, accept the Microsoft licence and download the VHD file ...)

But I have already prepared a 'ready to use' Nanoserver VHD for the SwarmMSKit : mount/unmount/djoin with dism tool for injecting the latest KB/Hotfixs, binaries (curl, docker, swarm, consul, vault, etc...), install the Windows features (containers, compute Hyper-V, IIS, etc...). You have only to download this file.

######This prepared VHD reference is up to date, the below Powershell script has already been performed on it :
	$ci = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
	Invoke-CimMethod -InputObject $ci -MethodName ApplyApplicableUpdates
	Restart-Computer; exit

######Initial Installation of Docker in the NanoServer (already done)
	Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
	Install-Package -Name docker -ProviderName DockerMsftProvider
	Restart-computer -force
	Import-Module DockerMsftProvider
	start-service docker
	docker pull microsoft/nanoserver
	docker tag microsoft/nanoserver nanoserver

SwarmMSKit-Setup requirements
-----

Any Windows OS whit the feature Hyper-V Installed like :
Windows 10 Pro or Entreprise Version 
Windows Server 2008 R2 Standard or Datacenter 
Windows Server 2016 Standard or Datacenter 

(tests and validate on Windows Server 2016 and Windows 10 Professional, any feedback are welcome !)

Powershell Version v3 or higher

Clone this 

Download the NanoServerDataCenter.vhd file from this Google Drive address :

https://drive.google.com/drive/folders/0BzqZR1dT_FQgRlcxRG9PSEVmUVk?usp=sharing

And that's it !




SwarmMSKit - Beginning
-----

######Set constants/variables in the SwarmMSKitProvisioning.ps1 file :
	WorkDir              = "C:\SwarmMSKit"
	VMPath               = "$global:WorkDir\VHD_Files"
	MediaPath            = "$global:WorkDir\W2K16"
	ToolsSource          = "$global:WorkDir\ToolsSource"
	ServicingPackages    = "$global:WorkDir\ServicingPackages"

######IP Configuration of your first VM NanoServer and VM Switch Hyper-V configuration :

	IPAddress      = "10.1.0.24"
	GatewayAddress = "10.1.0.1"
	SubnetMask     = "255.255.255.0"
	DNSAddresses   = "10.1.0.1"
	Subnet         = "10.1.0."
	VMSwitch       = "InternalNetwork"

######System Configuration for our NanoServer VM, 2 vCPU and 2 Go Ram
	VMProcessor           = 2
	VMRam                 = 2048MB

######AD Credential which will be the admin NanoServer account
	Username              = "FBOUKEZZOULA\Administrateur"
	clearadminPassword    = "YourPassWord"
	DomainName            = "FBOUKEZZOULA"

######Name prefix (Netbios/Hostname of the NanoServer and AD computer Names & Name in Hyper-V : Nano-Manager-1, Nano-Worker-1, Nano-Worker-2, etc...)
	ContainerHostName = "Nano-"

######Number of your Cluster Swarm members 
	ServersInCluster   = 3

######Our dedicated TCP Port for our Cluster Swarm Service
	SwarmClusterPort = "2017"


SwarmMSKit-Usage
-----

######ExecutionPolicy
	Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force 
	or
	Set-ExecutionPolicy Unrestricted

######Connect to the new NanoServer VM with WinRM protocol :
	Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
	Restart-Service winrm

Then run the SwarmMSKitProvisioning.ps1 file ...

When it's finish ...

* set DOCKER_HOST=tcp://@YourFirstIP:@YourClusterSwarmPort

######Examples :
	set DOCKER_HOST=tcp://10.1.0.24:2017
	docker images
	docker run -it nanoserver powershell
	docker run -it nanoserver cmd
	docker login -u admin -p admin123 @YourFirstIP:8123
	docker push nanoserver


SwarmMSKit-Youtube channel
-----

Stay tunned, very soon ...

Meanwhile, have a look on the screenshots (folder pics)


















