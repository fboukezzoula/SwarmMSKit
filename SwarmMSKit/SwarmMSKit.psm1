Set-StrictMode -version 3
$ErrorActionPreference = "Stop"


# Import localized strings
Import-LocalizedData Strings -FileName SwarmMSKit.Strings.psd1 -ErrorAction SilentlyContinue


# Simple pause function for waiting the VM booting or waiting the tools installation, etc ...
Function global:Pause  {
 
        param([int]$Seconds,[String]$ContainerHostNameNodeCreate)

        Write-Host " "
        Write-Host "Wait while NanoServer VM $ContainerHostNameNodeCreate is performing post-installation tasks and for booting ..."
        Write-Host " "
        Start-Sleep -Seconds $Seconds
}

# function calling the New-NanoServerImage function embedded with the ISO of Windows Servrer 2016, module found in the folder NanoServerImageGenerator
# I've to update the NanoServerImageGenerator.psm1 file (lines between 2510 and 2518)

Function global:NewNanoServerImage-Domain  {

    param(    
    [String]$ServicingPackages,
    [String]$VMPath,
    [String]$WorkDir,
    $adminPassword,
    [String]$MediaPath,
    [String]$ContainerHostName,
    [int]$InterfaceNameOrIndex, 
    [String]$IPAddress, 
    [String]$GatewayAddress, 
    [String]$SubnetMask, 
    [String]$DNSAddresses,
    [String]$DomainName)
             
    $DomainBlobPath = "$WorkDir\DJOIN_$ContainerHostName.TXT"
   
    #Remove-Item -Path $VMPath -Force -Recurse -ErrorAction SilentlyContinue

    # we integrated/join automatically the NanoServer VM in an Active Directory Domain with the DJOIN command and use the blob file during the Nanoserver installation
    $Command_Join = "DJOIN /provision /domain $DomainName /machine $ContainerHostName /REUSE /savefile $DomainBlobPath"
    Invoke-Expression $Command_Join

    # Notice that we have to install the latest KB/Hotfixs for Windows Server 2016
    New-NanoServerImage `
                -ServicingPackagePath @("$ServicingPackages\Windows-KB3176936-x64.cab", "$ServicingPackages\Windows-KB3192366-x64.cab") `
                -Edition Datacenter `
                -DeploymentType Guest `
                -AdministratorPassword  $adminPassword `
                -MediaPath $MediaPath `
                -BasePath $WorkDir\Base `
                -TargetPath $WorkDir\VHD_Files\$ContainerHostName.vhd `
                -MaxSize 10GB `
                -InterfaceNameOrIndex $InterfaceNameOrIndex -Ipv4Address $IPAddress -Ipv4SubnetMask $SubnetMask -Ipv4Gateway $GatewayAddress -Ipv4Dns $DNSAddresses `
                -Containers -Compute -EnableRemoteManagementPort -SetupCompleteCommand @("set LOCALAPPDATA=%USERPROFILE%\AppData\Local","PowerShell `"Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force`"","PowerShell `". C:\Windows\Setup\Scripts\NanoSetup.ps1`"")`
                -DomainBlobPath $DomainBlobPath
} 

# This function will create a start execution script and will be execute when the NanoServer VM will be boot the first time : set all the FW rules for Docker, Consul, Swarm, Private Registry (Nexus OSS Free binaries repository) for our docker images, WinRM, File Sharing, etc .. and
# performing several tasks like disable ipv6 on all adapters, disable all unused adapters, set the Time zone (Paris in this case) and set the static IPv4 configuration, etc ...
Function global:NanoSetup {

param([int]$SwarmClusterPort,[String]$DestinationFolder,[String]$ContainerIPAdress,[String]$GatewayAddress,[String]$SubnetMask,[String]$DNSAddresse) 

$NanoSetup = @" 

# Below, several FW Rules for enabled file sharing access to the container, Docker Daemon, Swarm, Consul, Vault, etc ...

# Enabled file sharing access to the Container
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes

# DockerDaemon default TCP Ports : 2375 and 2376 (TLS)
netsh advfirewall firewall add rule name="Docker daemon 2375" dir=in action=allow protocol=TCP localport=2375
netsh advfirewall firewall add rule name="Docker daemon TLS 2376" dir=in action=allow protocol=TCP localport=2376

netsh advfirewall firewall add rule name="Docker daemon Swarm $SwarmClusterPort" dir=in action=allow protocol=TCP localport=$SwarmClusterPort    

# Consul - Server RPC (Default 8300). This is used by servers to handle incoming requests from other agents. TCP only.
netsh advfirewall firewall add rule name="Consul - Server RPC" dir=in action=allow protocol=TCP localport=8300

# Consul - Serf LAN (Default 8301). This is used to handle gossip in the LAN. Required by all agents. TCP and UDP.
netsh advfirewall firewall add rule name="Consul - Serf LAN - TCP" dir=in action=allow protocol=TCP localport=8301
netsh advfirewall firewall add rule name="Consul - Serf LAN - UDP" dir=in action=allow protocol=UDP localport=8301

# Consul - Serf WAN (Default 8302). This is used by servers to gossip over the WAN to other servers. TCP and UDP.
netsh advfirewall firewall add rule name="Consul - Serf WAN - TCP" dir=in action=allow protocol=TCP localport=8302
netsh advfirewall firewall add rule name="Consul - Serf WAN - UDP" dir=in action=allow protocol=UDP localport=8302

# Consul - CLI RPC (Default 8400). This is used by all agents to handle RPC from the CLI. TCP only.
netsh advfirewall firewall add rule name="Consul - CLI RPC" dir=in action=allow protocol=TCP localport=8400

# Consul - HTTP API (Default 8500). This is used by clients to talk to the HTTP API. TCP only.
netsh advfirewall firewall add rule name="Consul - HTTP API" dir=in action=allow protocol=TCP localport=8500
netsh advfirewall firewall add rule name="Consul - HTTP API" dir=out action=allow protocol=TCP localport=8500

# Consul - DNS Interface (Default 8600). Used to resolve DNS queries. TCP and UDP.
netsh advfirewall firewall add rule name="Consul - DNS Interface - TCP" dir=out action=allow protocol=TCP localport=8600
netsh advfirewall firewall add rule name="Consul - DNS Interface - UDP" dir=out action=allow protocol=UDP localport=8600

# Vault (Default 8200). 
netsh advfirewall firewall add rule name="Vault - Server" dir=in action=allow protocol=TCP localport=8200

# Nexus for our Private Registry (Default 8081 and 8123). 
netsh advfirewall firewall add rule name="Nexus IHM - SwarmMSKit Private Registry" dir=in action=allow protocol=TCP localport=8081
netsh advfirewall firewall add rule name="SwarmMSKit Private Registry" dir=in action=allow protocol=TCP localport=8123

#disable ipv6 on all adapters
Get-NetAdapterBinding -ComponentID 'ms_tcpip6' | disable-NetAdapterBinding -ComponentID ms_tcpip6 -PassThru

#disable all unused adapters
#Get-NetAdapter | ? { `$_.status -eq "Disconnected" } | Disable-NetAdapter -Confirm:`$false

`$Name = "Paris"
`$SetTimeZoneParis = [system.timezoneinfo]::GetSystemTimeZones() | Where-Object {`$_.ID -like "*`$Name*" -or `$_.DisplayName -like "*`$Name*" } | Select-Object -ExpandProperty ID
tzutil.exe /s `$SetTimeZoneParis

#required for some cmdlets to work properly
set LOCALAPPDATA=%USERPROFILE%\AppData\Local

#declare IP variables
`$IP = "$ContainerIPAdress"
`$MaskBits = 24 # This means subnet mask = 255.255.255.0
`$Gateway = "$GatewayAddress"
`$IPType = "IPv4"

#get an adapter that is up to apply IP information to
#note this is just for example and grabbing the first up adapter may not be appropriate for your environment
`$upIndex = Get-NetAdapter | ? {`$_.Status -eq "Up" } | Select-Object -First 1 | Select-Object -ExpandProperty ifIndex

#clear any existing IP configuration
Remove-NetIPAddress -InterfaceIndex `$upIndex -AddressFamily `$IPType -Confirm:`$false

#set specifiec IP address
Get-NetAdapter -InterfaceIndex `$upIndex | New-NetIPAddress -AddressFamily `$IPType -IPAddress `$IP -PrefixLength `$MaskBits -DefaultGateway `$Gateway

#set DNS for up adapter
Set-DnsClientServerAddress -InterfaceIndex `$upIndex -ServerAddresses ("$DNSAddresse")


Shutdown /r /t 0

"@

$NanoSetup > $DestinationFolder 

}

# create the tree folders ans copy the severals tools inside the new provisionning NanoServer VM
Function global:CopyToolsToImage {

    param([String]$ToolsSource,[String]$DestinationFolderTargetMountPath)     

    cp $ToolsSource\*.exe "$DestinationFolderTargetMountPath\Windows\System32" -Recurse -Force
  
    New-Item -Type Directory -Path "$DestinationFolderTargetMountPath\Logs\vault-consul" -Force | Out-Null
    New-Item -Type Directory -Path "$DestinationFolderTargetMountPath\Logs\swarm" -Force | Out-Null
    New-Item -Type Directory -Path "$DestinationFolderTargetMountPath\Logs\dockerdaemon" -Force | Out-Null

    xcopy $ToolsSource\consul_web_ui\* "$DestinationFolderTargetMountPath\consul\consul_web_ui" /S /I /Y        
    New-Item -Type Directory -Path "$DestinationFolderTargetMountPath\consul\database" -Force | Out-Null

    xcopy $ToolsSource\OSImage\* "$DestinationFolderTargetMountPath\OSImage" /S /I /Y

    xcopy $ToolsSource\vault\ssl\* "$DestinationFolderTargetMountPath\vault\ssl" /S /I /Y
    
}

# create and configure a new VM host on Hyper-V
Function global:Create-Set-VM-Hyper-V {

    param([String]$VMSwitch,
    [String]$VMPath,
    [String]$VMName,
    [Int]$VMProcessor,
    [String]$VMRam) 

    New-VM -Name "$VMName" -MemoryStartupBytes $VMRam -SwitchName "$VMSwitch" -VHDPath "$VMPath\$VMName.vhd" -Path "$VMPath" -Generation 1

    Set-VMMemory $VMName -DynamicMemoryEnabled $false

    Set-VMProcessor -VMName $VMName -Count $VMProcessor -Reserve 10 -Maximum 75 -RelativeWeight 200 -ExposeVirtualizationExtensions $true

    Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On 
     
}

# enable and start a created VM host on Hyper-V
Function global:Enabled-Start-VM-Hyper-V {

    param([String]$VMName)

    $vm = get-vm

    Foreach($v in $vm)

     {
  
      Get-VMIntegrationService -VM $v |

        Foreach-object {

          if(!($_.enabled))

            {
                Enable-VMIntegrationService -Name $_.name -VM $v
                Start-VM -Name $VMName
            }
        } 
        
     }
 }

# telnet WinRM service (TCP Port: 5985) on the new NanoServer VM to be sure that it was correctly reboot and online before performing several tasks (installation docker, swarm, consul, vault, nexus3, etc ...) 
Function global:Wait-WinRM-Reachable {

    param([String]$ContainerIPNodeCreate)

    Do
    {        
        #$a = Test-NetConnection ((Get-VMNetworkAdapter -VMName $ContainerHostName).IpAddresses  | where { $_ -match "\." }) -Port 5985 -ErrorAction SilentlyContinue
        $a = Test-NetConnection $ContainerIPNodeCreate -Port 5985 -ErrorAction SilentlyContinue
        $result = $a.TcpTestSucceeded       

    } While ($result -ne "True")

}

# function to install and configure the Docker Daemon on each new NanoServer VM : we don't forget to use set in the daemon.json configuration file the @IP of our consul registry discovery service, private registry, etc ... 
Function global:DockerInstallation {

    param([bool]$SwarmManager,[String]$IPConsulMaster) 

    setx path "%PATH%;$env:ProgramFiles\docker\"
    
    # To prevent an error is thrown indicating a timeout event, the following PowerShell command  fix it
    Set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Containers' -Name VSmbDisableOplocks -Type DWord -Value 1 -Force

    $command = "dockerd --register-service"  
    Invoke-Expression $command 

    Start-Service Docker
    Get-Service Docker 

    docker load -i C:\OSImage\nanoserver.tar | Out-Host | Out-Null
    remove-item C:\OSImage -recurse -force | Out-Host | Out-Null

    docker tag microsoft/nanoserver nanoserver 


    Stop-Service Docker 

    $advertise = $IPConsulMaster + ":2375"
    $consul    = $IPConsulMaster + ":8500"

    $daemon_json_file = "c:\ProgramData\docker\config\daemon.json"

    $json = @"
{
    "hosts": ["tcp://0.0.0.0:2375","npipe://"],	
    "insecure-registries": ["$IPConsulMaster`:8123"]
}
"@


    $jobj = ConvertFrom-Json -InputObject $json

    if ($SwarmManager -eq "$True") {
    
    $jobj | add-member "cluster-store" "consul://$consul" -MemberType NoteProperty
    $jobj | add-member "cluster-advertise" "$advertise" -MemberType NoteProperty

    }

    ConvertTo-Json $jobj | Out-File $daemon_json_file  

    (Get-Content -path "$daemon_json_file" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$daemon_json_file"

    if (Test-Path $env:ProgramData\docker.pid) {Remove-Item $env:ProgramData\docker.pid -Force} 
    Set-Service -name Docker -startupType Disabled

    # we install the Docker Daemon as an Windows Service with nssm
    nssm install SwarmMSKit-DockerDaemon dockerd.exe | Out-Null 
    nssm set SwarmMSKit-DockerDaemon Description "SwarmMSKit-DockerDaemon Docker Daemon Service" | Out-Null
    nssm set SwarmMSKit-DockerDaemon AppStdout C:\Logs\dockerdaemon\service.log | Out-Null
    nssm set SwarmMSKit-DockerDaemon AppStderr C:\Logs\dockerdaemon\service.log | Out-Null
    nssm start SwarmMSKit-DockerDaemon | Out-Null

    Write-Host " "
    docker --version
    Write-Host " "
    docker info
    Write-Host " "
    docker images
    Write-Host " "
    
}

# function to install and configure the Vault Server Secret Management Store on the first created NanoServer VM of the cluster swarm (which is an Consul Server and an Swarm Manager too) 
Function global:VaultServer {

param([String]$IPVaultServer) 

$DestinationFolder_hcl_configuration_file = "c:\vault\vault-fboukezzoula.hcl"
$DestinationFolder_vault_keys_file = "c:\vault\vaul_init.txt"


# Vault hcl/json configuration file, notice that you can use a TLS connection. 
$hcl_configuration_file = @" 

disable_mlock = true
default_lease_ttl = "24h"
max_lease_ttl = "24h"

backend "consul" {
    address = "$IPVaultServer`:8500"
    path = "vault"
}

listener "tcp" {
    address = "$IPVaultServer`:8200"
    tls_disable = 1
    #tls_enable = 1
    tls_cert_file = "c://vault//ssl//cert.pem"
    tls_key_file = "c://vault/ssl//key.pem"

}

"@
         
    $hcl_configuration_file | Out-File $DestinationFolder_hcl_configuration_file 

    (Get-Content -path "$DestinationFolder_hcl_configuration_file" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$DestinationFolder_hcl_configuration_file"

    Write-Host " "
    Write-Host "Installation and configuration of the VAULT Server ... Please wait ..."
    Write-Host " "

    # we install the Vault Server as an Windows Service with nssm
    nssm install SwarmMSKit-VaultServer vault server -config="$DestinationFolder_hcl_configuration_file" | Out-Null 
    nssm set SwarmMSKit-VaultServer Description "Securely managing secrets and encrypting data in-transit for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-VaultServer AppStdout C:\Logs\vault-consul\service-vault.log | Out-Null
    nssm set SwarmMSKit-VaultServer AppStderr C:\Logs\vault-consul\service-vault.log | Out-Null
    nssm start SwarmMSKit-VaultServer | Out-Null
    Write-Host " "

    # Initialisation the Vault Secret Management Store and write in a file the root token and all the keys for unsealing

    $CommandInitVault="vault init -address=http://" + $IPVaultServer + ":8200 > $DestinationFolder_vault_keys_file" 
    Invoke-Expression $CommandInitVault

    # UnSealed the Vault Secret Management Store; so we can create keys and browse the store with the consul UI

    $UnsealKeys = gc $DestinationFolder_vault_keys_file 

    $AllUnsKeyseal = $UnsealKeys.split(' ',4)

    foreach ($key in $AllUnsKeyseal[3,7,11,15,19]) {
        
        Write-Host " "
        Write-Host "vault unseal $key"
        $CommandInitVault = "vault unseal -address=http://" + $IPVaultServer + ":8200 $key"
        Invoke-Expression $CommandInitVault
        Write-Host " "

    }
}

# function to install and configure the Consul Server
Function global:ConsulServer {

    param ([String]$IPVM,[String]$IPConsulServer,[int]$BootstrapExpectServers)

    #Write-Host "Number of Consul Server(s) in the cluster Swarm : " $BootstrapExpectServers
    
    # we install the Consul Server as an Windows Service with nssm
    Write-Host " "
    nssm install SwarmMSKit-ConsulServer consul.exe "agent -server -data-dir C:\consul\database\ -ui-dir C:\consul\consul_web_ui\ -bootstrap-expect $BootstrapExpectServers -bind=""$IPVM"" -client=""$IPVM"" -dc=""nano-swarm""" | Out-Null
    nssm set SwarmMSKit-ConsulServer Description "Discovery Service and Key/Value Store use for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-ConsulServer AppStdout C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm set SwarmMSKit-ConsulServer AppStderr C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm start SwarmMSKit-ConsulServer | Out-Null
    Write-Host " "

    $ConsulServerReference = $IPConsulServer + ":8400"

    if ($BootstrapExpectServers -gt 1) {

    Write-Host " "
    consul join -rpc-addr="$ConsulServerReference" $IPVM
    Write-Host " "
    }

}

# function to install and configure the Consul Agent (on each Swarm Worker of our Cluster Swarm)
Function global:ConsulAgent {

    param ([String]$IPVM,[String]$IPConsulServer) 

    $ConsulServerReference = $IPConsulServer + ":8400"

    # we install the Consul Agent as an Windows Service with nssm
    Write-Host " "
    nssm install SwarmMSKit-ConsulAgent consul.exe "agent -data-dir C:\consul\database\ -ui-dir C:\consul\ui\ -bind=""$IPVM"" -client=""$IPVM"" -dc=""nano-swarm""" | Out-Null
    nssm set SwarmMSKit-ConsulAgent Description "Discovery Service and Key/Value Store use for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-ConsulAgent AppStdout C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm set SwarmMSKit-ConsulAgent AppStderr C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm start SwarmMSKit-ConsulAgent | Out-Null

    Write-Host " "
    consul join -rpc-addr="$ConsulServerReference" $IPVM
    Write-Host " "
}

# function to install and configure the Swarm Node/Worker
Function global:SwarmWorker {

    param ([String]$IPVM,[String]$IPConsulMaster) 

    $advertise = "--advertise=" + $IPVM + ":2375"
    $consul    = $IPConsulMaster + ":8500"
   
    # we install the Swarm Node/Worker as an Windows Service with nssm
    Write-Host " "
    nssm install SwarmMSKit-Worker swarm "join $advertise consul://$consul" | Out-Null
    nssm set SwarmMSKit-Worker Description "Cluster Swarm under NanoServer - Swarm Node" | Out-Null
    nssm set SwarmMSKit-Worker AppStdout c:\Logs\swarm\service.log | Out-Null
    nssm set SwarmMSKit-Worker AppStderr c:\Logs\swarm\service.log | Out-Null
    nssm start SwarmMSKit-Worker | Out-Null
    Write-Host " "

}

# function to install and configure the Swarm Manager
Function global:SwarmManager {

    param ([String]$IPVM,[String]$IPConsulMaster, [int]$SwarmClusterPort) 

    $SwarmManagerDaemon = $IPVM + ":$SwarmClusterPort"
    $consul    = $IPConsulMaster + ":8500"

    # we install the Swarm Manager as an Windows Service with nssm   
    nssm install SwarmMSKit-Manager swarm manage "-H tcp://$SwarmManagerDaemon consul://$consul" | Out-Null
    nssm set SwarmMSKit-Manager Description "Cluster Swarm under NanoServer - Swarm Manager" | Out-Null
    nssm set SwarmMSKit-Manager AppStdout c:\Logs\swarm\service.log | Out-Null
    nssm set SwarmMSKit-Manager AppStderr c:\Logs\swarm\service.log | Out-Null
    nssm start SwarmMSKit-Manager | Out-Null
}
 
# function to install and configure a dedicated private registry for hosting our docker images. We use the last version of Nexus OSS which is free 
Function global:SwarmMSKit-Private-Registry {

    param([String]$ToolsSource,[String]$Username,[String]$Password,[String]$IPVM)

    $NexusArchive = "$ToolsSource\nexus-3.2.0-01-win64.zip"

    $PasswordRoot  = ConvertTo-SecureString $Password -AsPlainText -Force

    $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username,$PasswordRoot    
   
    Expand-Archive -Path $NexusArchive -DestinationPath \\$IPVM\c$\PrivateRegistry -Force | Out-Null    
   
    $InstallServiceSwarmMSKitPrivateRegistry = "c:\PrivateRegistry\nexus-3.2.0-01\bin\nexus.exe /install SwarmMSKit-PrivateRegistry"
    $StartServiceSwarmMSKitPrivateRegistry = "c:\PrivateRegistry\nexus-3.2.0-01\bin\nexus.exe /start SwarmMSKit-PrivateRegistry"
    
    Write-Host " "
    Write-Host "Install the SwarmMSKit-Private-Registry service to store our Docker images ..."
    Write-Host " "
     

    Invoke-Command -ComputerName $IPVM -Credential $Cred -ScriptBlock {Invoke-Expression $using:InstallServiceSwarmMSKitPrivateRegistry}  | Out-Host | Out-Null
    Invoke-Command -ComputerName $IPVM -Credential $Cred -ScriptBlock {Invoke-Expression $using:StartServiceSwarmMSKitPrivateRegistry}  | Out-Host | Out-Null

    
}

