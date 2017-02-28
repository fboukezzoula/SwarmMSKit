# Purge the Temp folder of the mount image if exist for the next loop process
Function global:PurgeTempMountFolder {

    param([String]$TempMountFolder)

    if ((Test-Path -Path $TempMountFolder)) {    
        Remove-Item -Path $TempMountFolder -Recurse -Force | Out-Null         
    }     
}

# Simple pause function for waiting the VM booting or waiting the tools installation, etc ...
Function global:Pause  {
 
        param([int]$Seconds,[String]$ContainerHostNameNodeCreate)

        " "
        "Wait while NanoServer VM $ContainerHostNameNodeCreate is performing post-installation tasks and for booting ..."
        " "
        Start-Sleep -Seconds $Seconds
}

# Create and configure a new VM host in Hyper-V
Function global:Create-Set-VM-Hyper-V {

    param([String]$VMSwitch,
    [String]$VMPath,
    [String]$VMName,
    [Int]$VMProcessor,
    [String]$VMRam) 

    New-VM -Name "$VMName" -MemoryStartupBytes $VMRam -SwitchName "$VMSwitch" -VHDPath "$VMPath\$VMName.vhd" -Path "$VMPath"  -Generation 1
    
    Set-VMMemory $VMName -DynamicMemoryEnabled $false

    Set-VMProcessor -VMName $VMName -Count $VMProcessor -Reserve 10 -Maximum 75 -RelativeWeight 200 -ExposeVirtualizationExtensions $true

    Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On 
     
}

# Enable and start a created VM host on Hyper-V
Function global:Enabled-VM-Hyper-V {

    param([String]$VMName)

    $vm = get-vm

    Foreach($v in $vm)

     {
  
      Get-VMIntegrationService -VM $v |

        Foreach-object {

          if(!($_.enabled))

            {
                Enable-VMIntegrationService -Name $_.name -VM $v
            }
        } 
        
     }
 }

# Telnet WinRM service (TCP Port: 5985) on the new NanoServer VM to be sure that it was correctly reboot and online before performing several tasks (installation docker, swarm, consul, vault, nexus3, etc ...) 
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

    param([bool]$SwarmManager,[bool]$EnabledDockerDaemonTLS,[String]$IPConsulMaster,[String]$ContainerIPNodeCreate,[String]$Username,[String]$clearadminPassword) 
 
    setx path "%PATH%;$env:ProgramFiles\docker\"
    
    # To prevent an error is thrown indicating a timeout event, the following PowerShell command  fix it
    Set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Containers' -Name VSmbDisableOplocks -Type DWord -Value 0 -Force

    Stop-Service Docker 
    
    $consul    = $IPConsulMaster + ":8500"

    $daemon_json_file = "c:\ProgramData\docker\config\daemon.json"

if ($EnabledDockerDaemonTLS -eq "$True") {

    $advertise = $IPConsulMaster + ":2376"

    $json = @"
{
    "tlscacert":  "C:\\ProgramData\\docker\\certs.d\\ca.pem",
    "tlsverify":  true,
    "hosts":  [
                  "tcp://0.0.0.0:2376",
                  "npipe://"
              ],
    "tlscert":  "C:\\ProgramData\\docker\\certs.d\\cert.pem",
    "tlskey":  "C:\\ProgramData\\docker\\certs.d\\key.pem",
    "insecure-registries": ["$IPConsulMaster`:8123"]
}
"@
    $Source = "\\$IPConsulMaster\c$\ProgramData\OpenSSL\TLS"
    $Dest   = "C:\ProgramData\docker\certs.d"

    New-Item -Type Directory -Path $Dest -Force | Out-Null

    $MapDrive ="net use S: $Source /user:$Username $clearadminPassword"
    Invoke-Expression $MapDrive

    Copy-Item -Path S:\ca.pem -Destination $Dest\ca.pem
    Copy-Item -Path S:\$ContainerIPNodeCreate-cert.pem -Destination $Dest\cert.pem 
    Copy-Item -Path S:\$ContainerIPNodeCreate-priv-key.pem -Destination $Dest\key.pem 

} else {

    $advertise = $IPConsulMaster + ":2375"

    $json = @"
{
    "hosts": ["tcp://0.0.0.0:2375","npipe://"],	
    "insecure-registries": ["$IPConsulMaster`:8123"]
}
"@

}
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

    " "
    docker --version
    " "
    docker info
    " "
    docker images
    " "    
}

# function to make several installations :
# install and configure the Vault Server Secret Management Store on the first created NanoServer VM of the cluster swarm (which is an Consul Server and an Swarm Manager too) 
# install and configure a dedicated private registry for hosting our docker images. We use the last version of Nexus OSS which is free 
# install and configure a IHM/GUI like DDC UCP (portainer)

Function global:VaultServer-PrivateRegistry-UCP {

    param([String]$IPVaultServer,[int]$SwarmClusterPort,[bool]$EnabledDockerDaemonTLS) 

    $DestinationFolder_hcl_configuration_file = "c:\vault\vault-fboukezzoula.hcl"
    $DestinationFolder_vault_keys_file = "c:\vault\vaul_init.txt"
    $DestinationFolder_UnsealVaultScript = "c:\vault\unseal_vault.cmd"

    New-Item -Type Directory -Path "c:\vault" -Force | Out-Null     

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

}

"@
         
    $hcl_configuration_file | Out-File $DestinationFolder_hcl_configuration_file 

    (Get-Content -path "$DestinationFolder_hcl_configuration_file" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$DestinationFolder_hcl_configuration_file"

    " "
    "Installation and configuration of the VAULT Server ... Please wait ..."
    " "

    # we install the Vault Server as an Windows Service with nssm
    nssm install SwarmMSKit-VaultServer vault server -config="$DestinationFolder_hcl_configuration_file" | Out-Null 
    nssm set SwarmMSKit-VaultServer Description "Securely managing secrets and encrypting data in-transit for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-VaultServer AppStdout C:\Logs\vault-consul\service-vault.log | Out-Null
    nssm set SwarmMSKit-VaultServer AppStderr C:\Logs\vault-consul\service-vault.log | Out-Null
    nssm start SwarmMSKit-VaultServer | Out-Null
    " "

    # Initialisation the Vault Secret Management Store and write in a file the root token and all the keys for unsealing

    $CommandInitVault="vault init -address=http://" + $IPVaultServer + ":8200 > $DestinationFolder_vault_keys_file" 
    Invoke-Expression $CommandInitVault

    # UnSealed the Vault Secret Management Store; so we can create keys and browse the store with the consul UI

    $UnsealKeys = gc $DestinationFolder_vault_keys_file 

    $AllUnsKeyseal = $UnsealKeys.split(' ',4)

    foreach ($key in $AllUnsKeyseal[3,7,11,15,19]) {
        
        " "
        "vault unseal $key"
        $CommandInitVault = "vault unseal -address=http://" + $IPVaultServer + ":8200 $key"
        Invoke-Expression $CommandInitVault
        " "
    }

    # Create a Powershell script and create a schedule task to execute this PowerShell script each time the VM NanoServer starts
    # This task it's for unsealing the Vault Store with the Unseal Keys create in the initi process
     
    foreach ($key in $AllUnsKeyseal[3,7,11,15,19]) {
        
        $CommandInitVault = "vault unseal -address=http://" + $IPVaultServer + ":8200 $key" ; Add-Content $DestinationFolder_UnsealVaultScript $CommandInitVault
    }
    
    $CreateSchedukeTask = "schtasks /create /tn 'Unseal Vault onStart' /tr $DestinationFolder_UnsealVaultScript /sc onstart /ru 'System'"
    Invoke-Expression $CreateSchedukeTask


    # INSTALLATION PRIVATE REGISTRY - SwarmMSKitPrivateRegistry

    $NexusArchive = "c:\tools\nexus-3.2.0-01-win64.zip"

    Expand-Archive -Path $NexusArchive -DestinationPath c:\PrivateRegistry -Force | Out-Null    
   
    $InstallServiceSwarmMSKitPrivateRegistry = "c:\PrivateRegistry\nexus-3.2.0-01\bin\nexus.exe /install SwarmMSKit-PrivateRegistry"
    $StartServiceSwarmMSKitPrivateRegistry = "c:\PrivateRegistry\nexus-3.2.0-01\bin\nexus.exe /start SwarmMSKit-PrivateRegistry"
    
    " "
    "Install the SwarmMSKit-Private-Registry service to store our Docker images ..."
    " "
     
    Invoke-Expression $InstallServiceSwarmMSKitPrivateRegistry | Out-Host | Out-Null
    Invoke-Expression $StartServiceSwarmMSKitPrivateRegistry   | Out-Host | Out-Null

    # INSTALLATION SwarmMSKit-UCP
        
    $PortainerArchive = "c:\tools\portainer.zip"

    " "
    "Installation and configuration of the Web Admin Cluster Swarm - Portainer (Like UCP of Docke Inc)  ... Please wait ..."
    " "  

    Expand-Archive -Path $PortainerArchive -DestinationPath c:\portainer -Force | Out-Null    
    
    $DestinationFolder_SwarmMSKit_UCP = "c:\portainer\portainer.cmd"

    $SWARM_HOST = "tcp://" + $IPVaultServer + ":$SwarmClusterPort"   
    
    $TLSverify = "--tlsverify --tlscacert=C:\\ProgramData\\docker\\certs.d\\ca.pem --tlscert=C:\\ProgramData\\docker\\certs.d\\cert.pem --tlskey=C:\\ProgramData\\docker\\certs.d\\key.pem"    

    # create the cmd file that will be run at the end - this bach launch the Portainer which is a simple but very cool management solution for Docker. 
    $CommandLaunchSwarmMSKit_UCP ="set portainerdir=""c:\portainer""" ; Add-Content $DestinationFolder_SwarmMSKit_UCP $CommandLaunchSwarmMSKit_UCP
    $CommandLaunchSwarmMSKit_UCP ="cd /d %portainerdir%" ; Add-Content $DestinationFolder_SwarmMSKit_UCP $CommandLaunchSwarmMSKit_UCP
    
    if ($EnabledDockerDaemonTLS -eq "$True") {
    
    $CommandLaunchSwarmMSKit_UCP =".\portainer.exe -H $SWARM_HOST --logo ""http://$IPVaultServer/logoSwarmMSKit.png"" --templates http://$IPVaultServer/templates.json $TLSverify" ; Add-Content $DestinationFolder_SwarmMSKit_UCP $CommandLaunchSwarmMSKit_UCP

    } else {

    $CommandLaunchSwarmMSKit_UCP =".\portainer.exe -H $SWARM_HOST --logo ""http://$IPVaultServer/logoSwarmMSKit.png"" --templates http://$IPVaultServer/templates.json" ; Add-Content $DestinationFolder_SwarmMSKit_UCP $CommandLaunchSwarmMSKit_UCP
    
    }

    $ExecutePortainer = "c:\portainer\portainer.cmd"   
    
    # create a scheduke task for onstart to run/launch the Portainer 
    $CreateSchedukeTask = "schtasks /create /tn 'SwarmMSKit-UCP' /tr $ExecutePortainer /sc onstart /ru 'System'" 
    
    # create the json template file for the app services in the IHM
    $template_json ="c:\inetpub\wwwroot\templates.json"
    $string = gc $template_json
    $string.replace("##PORTAINER_HOST##","$IPVaultServer") | out-file $template_json 
    
    (Get-Content -path "$template_json" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$template_json" 


    $DestinationFolder_DockerHostedRepository = "c:\PrivateRegistry\dockerhost.json"

$DockerHostedRepository = @" 
{
  "name": "swarmmskit",
  "type" : "groovy",  
  "v1Enabled" : "true",
  "strictContentTypeValidation" : "true",
  "content": "repository.createDockerHosted('swarmmskit',8123,4443)"
}
"@

    $DockerHostedRepository| Out-File $DestinationFolder_DockerHostedRepository 

    (Get-Content -path "$DestinationFolder_DockerHostedRepository" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$DestinationFolder_DockerHostedRepository"

    " "
    "Create a DockerHost Repository called 'swarmmskit' for our Docker images in the deployed ..."
    "Please wait while the Private Registry is running and wait for the Docker Hosted Repository has been created ...."
    " "

    $CreateDockerHostRepository      = "curl -s -u admin:admin123 --header ""Content-Type: application/json"" ""http://$IPVaultServer"+":8081/service/siesta/rest/v1/script/"" -d @$DestinationFolder_DockerHostedRepository"
    $RunGroovyDockerHostRepository   = "curl -s -X POST -u admin:admin123 --header ""Content-Type: text/plain"" ""http://$IPVaultServer"+":8081/service/siesta/rest/v1/script/swarmmskit/run""" 

    " "
    $CreateDockerHostRepository
    " "
    $RunGroovyDockerHostRepository
    " "
    
    
    Start-Sleep -Seconds 75
    
    Do
    {        
        $a = Test-NetConnection $IPVaultServer -Port 8081 -ErrorAction SilentlyContinue
        $result = $a.TcpTestSucceeded       

    } While ($result -ne "True")

    Invoke-Expression $CreateDockerHostRepository -ErrorAction SilentlyContinue | Out-Host | Out-Null
    Invoke-Expression $RunGroovyDockerHostRepository -ErrorAction SilentlyContinue | Out-Host | Out-Null
    
       
}

# function to install and configure the Consul Server
Function global:ConsulServer {

    param ([String]$IPVM,[String]$IPConsulServer,[int]$BootstrapExpectServers)

    #Write-Host "Number of Consul Server(s) in the cluster Swarm : " $BootstrapExpectServers
    
    # we install the Consul Server as an Windows Service with nssm
    " "
    nssm install SwarmMSKit-ConsulServer consul.exe "agent -server -data-dir C:\consul\database\ -ui-dir C:\consul\consul_web_ui\ -bootstrap-expect $BootstrapExpectServers -bind=""$IPVM"" -client=""$IPVM"" -dc=""nano-swarm""" | Out-Null
    nssm set SwarmMSKit-ConsulServer Description "Discovery Service and Key/Value Store use for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-ConsulServer AppStdout C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm set SwarmMSKit-ConsulServer AppStderr C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm start SwarmMSKit-ConsulServer | Out-Null
    " "

    $ConsulServerReference = $IPConsulServer + ":8400"

    if ($BootstrapExpectServers -gt 1) {

    " "
    consul join -rpc-addr="$ConsulServerReference" $IPVM
    " "
    }

}

# function to install and configure the Consul Agent (on each Swarm Worker of our Cluster Swarm)
Function global:ConsulAgent {

    param ([String]$IPVM,[String]$IPConsulServer) 

    $ConsulServerReference = $IPConsulServer + ":8400"

    # we install the Consul Agent as an Windows Service with nssm
    " "
    nssm install SwarmMSKit-ConsulAgent consul.exe "agent -data-dir C:\consul\database\ -ui-dir C:\consul\ui\ -bind=""$IPVM"" -client=""$IPVM"" -dc=""nano-swarm""" | Out-Null
    nssm set SwarmMSKit-ConsulAgent Description "Discovery Service and Key/Value Store use for our Cluster Swarm NanoServer Windows" | Out-Null
    nssm set SwarmMSKit-ConsulAgent AppStdout C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm set SwarmMSKit-ConsulAgent AppStderr C:\Logs\vault-consul\service-consul.log | Out-Null
    nssm start SwarmMSKit-ConsulAgent | Out-Null

    " "
    consul join -rpc-addr="$ConsulServerReference" $IPVM
    " "
}

# function to install and configure the Swarm Node/Worker
Function global:SwarmWorker {

    param ([String]$IPVM,[bool]$EnabledDockerDaemonTLS,[String]$IPConsulMaster) 

    if ($EnabledDockerDaemonTLS -eq "$True") {

        $advertise = "--advertise=" + $IPVM + ":2376"

    } else {

        $advertise = "--advertise=" + $IPVM + ":2375"

    }


    $consul    = $IPConsulMaster + ":8500"
   
    # we install the Swarm Node/Worker as an Windows Service with nssm
    " "
    nssm install SwarmMSKit-Worker swarm "join $advertise consul://$consul" | Out-Null
    nssm set SwarmMSKit-Worker Description "Cluster Swarm under NanoServer - Swarm Node" | Out-Null
    nssm set SwarmMSKit-Worker AppStdout c:\Logs\swarm\service.log | Out-Null
    nssm set SwarmMSKit-Worker AppStderr c:\Logs\swarm\service.log | Out-Null
    nssm start SwarmMSKit-Worker | Out-Null
   " "
}

# function to install and configure the Swarm Manager
Function global:SwarmManager {

    param ([String]$IPVM,[bool]$EnabledDockerDaemonTLS,[String]$IPConsulMaster, [int]$SwarmClusterPort) 

    $SwarmManagerDaemon = $IPVM + ":$SwarmClusterPort"
    $consul    = $IPConsulMaster + ":8500"

if ($EnabledDockerDaemonTLS -eq "$True") {

    $TLSverify = "--tlsverify --tlscacert=C:\\ProgramData\\docker\\certs.d\\ca.pem --tlscert=C:\\ProgramData\\docker\\certs.d\\cert.pem --tlskey=C:\\ProgramData\\docker\\certs.d\\key.pem"

    nssm install SwarmMSKit-Manager swarm manage "$TLSverify -H tcp://$SwarmManagerDaemon consul://$consul" | Out-Null

} else {

    # we install the Swarm Manager as an Windows Service with nssm   
    nssm install SwarmMSKit-Manager swarm manage "-H tcp://$SwarmManagerDaemon consul://$consul" | Out-Null

}
    nssm set SwarmMSKit-Manager Description "Cluster Swarm under NanoServer - Swarm Manager" | Out-Null
    nssm set SwarmMSKit-Manager AppStdout c:\Logs\swarm\service.log | Out-Null
    nssm set SwarmMSKit-Manager AppStderr c:\Logs\swarm\service.log | Out-Null
    nssm start SwarmMSKit-Manager | Out-Null
}
 
# This function will create a start execution script and will be execute when the NanoServer VM will be boot the first time : set all the FW rules for Docker, Consul, Swarm, Private Registry (Nexus OSS Free binaries repository) for our docker images, WinRM, File Sharing, etc .. and
# performing several tasks like disable ipv6 on all adapters, disable all unused adapters, set the Time zone (Paris in this case) and set the static IPv4 configuration, etc ...
Function global:NanoSetup {

    param([bool]$FireWallRules,[int]$SwarmClusterPort) 


 if ($FireWallRules -eq "$True") {

" "
"Set all the Firewall Rules for Docker Daemon, Consul, Swarm, Private Registry (Nexus OSS Free binaries repository) for our Docker images, WinRM, File Sharing"
"Performing several tasks like disable ipv6 on all adapters, disable all unused adapters, set the Time zone (Paris in this case) etc ... Please Wait ..."
" "

# Below, several FW Rules for enabled file sharing access to the container, Docker Daemon, Swarm, Consul, Vault, etc ...

# Enabled file sharing access to the Container
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes

# DockerDaemon default TCP Ports : 2375 and 2376 (TLS)
netsh advfirewall firewall add rule name="SwarmMSKit - Docker daemon 2375" dir=in action=allow protocol=TCP localport=2375
netsh advfirewall firewall add rule name="SwarmMSKit - Docker daemon TLS 2376" dir=in action=allow protocol=TCP localport=2376

netsh advfirewall firewall add rule name="SwarmMSKit - Docker daemon Swarm $SwarmClusterPort" dir=in action=allow protocol=TCP localport=$SwarmClusterPort    

# Consul - Server RPC (Default 8300). This is used by servers to handle incoming requests from other agents. TCP only.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - Server RPC" dir=in action=allow protocol=TCP localport=8300

# Consul - Serf LAN (Default 8301). This is used to handle gossip in the LAN. Required by all agents. TCP and UDP.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - Serf LAN - TCP" dir=in action=allow protocol=TCP localport=8301
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - Serf LAN - UDP" dir=in action=allow protocol=UDP localport=8301

# Consul - Serf WAN (Default 8302). This is used by servers to gossip over the WAN to other servers. TCP and UDP.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - Serf WAN - TCP" dir=in action=allow protocol=TCP localport=8302
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - Serf WAN - UDP" dir=in action=allow protocol=UDP localport=8302

# Consul - CLI RPC (Default 8400). This is used by all agents to handle RPC from the CLI. TCP only.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - CLI RPC" dir=in action=allow protocol=TCP localport=8400

# Consul - HTTP API (Default 8500). This is used by clients to talk to the HTTP API. TCP only.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - HTTP API" dir=in action=allow protocol=TCP localport=8500
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - HTTP API" dir=out action=allow protocol=TCP localport=8500

# Consul - DNS Interface (Default 8600). Used to resolve DNS queries. TCP and UDP.
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - DNS Interface - TCP" dir=out action=allow protocol=TCP localport=8600
netsh advfirewall firewall add rule name="SwarmMSKit - Consul - DNS Interface - UDP" dir=out action=allow protocol=UDP localport=8600

# Vault (Default 8200). 
netsh advfirewall firewall add rule name="SwarmMSKit - Vault - Server" dir=in action=allow protocol=TCP localport=8200

# Nexus for our Private Registry (Default 8081 and 8123). 
netsh advfirewall firewall add rule name="SwarmMSKit - Nexus IHM - Private Registry" dir=in action=allow protocol=TCP localport=8081
netsh advfirewall firewall add rule name="SwarmMSKit - Private Registry" dir=in action=allow protocol=TCP localport=8123

# Portainer - UCP - Interface web for the Cluster Swarm Administration 
netsh advfirewall firewall add rule name="SwarmMSKit - Portainer - UCP" dir=in action=allow protocol=TCP localport=9000

}
else {

    " "
    "Disable Microsoft Firewall ..."
    " "
    netsh Advfirewall set allprofiles state off

}

#disable ipv6 on all adapters
Get-NetAdapterBinding -ComponentID 'ms_tcpip6' | disable-NetAdapterBinding -ComponentID ms_tcpip6 -PassThru

#disable all unused adapters
Get-NetAdapter | ? { $_.status -eq "Disconnected" } | Disable-NetAdapter -Confirm:$false

$Name = "Paris"
$SetTimeZoneParis = [system.timezoneinfo]::GetSystemTimeZones() | Where-Object {$_.ID -like "*$Name*" -or $_.DisplayName -like "*$Name*" } | Select-Object -ExpandProperty ID
tzutil.exe /s $SetTimeZoneParis

#required for some cmdlets to work properly
set LOCALAPPDATA=%USERPROFILE%\AppData\Local

} 

# function for setting the TCP/IP for the new VM NanoServer (static @IP)
Function Set-VMNetworkConfiguration {
    [CmdletBinding()]
    Param (

        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='DHCP',
                   ValueFromPipeline=$true)]
        [Parameter(Mandatory=$true,
                   Position=0,
                   ParameterSetName='Static',
                   ValueFromPipeline=$true)]
        [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,
 
        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='Static')]
        [String[]]$IPAddress=@(),
 
        [Parameter(Mandatory=$false,
                   Position=2,
                   ParameterSetName='Static')]
        [String[]]$Subnet=@(),
 
        [Parameter(Mandatory=$false,
                   Position=3,
                   ParameterSetName='Static')]
        [String[]]$DefaultGateway = @(),
 
        [Parameter(Mandatory=$false,
                   Position=4,
                   ParameterSetName='Static')]
        [String[]]$DNSServer = @(),
 
        [Parameter(Mandatory=$false,
                   Position=0,
                   ParameterSetName='DHCP')]
        [Switch]$Dhcp
    )
 
    $VM = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $NetworkAdapter.VMName } 
    $VMSettings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }    
    $VMNetAdapters = $VMSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData') 
 
    $NetworkSettings = @()
    foreach ($NetAdapter in $VMNetAdapters) {
        if ($NetAdapter.Address -eq $NetworkAdapter.MacAddress) {
            $NetworkSettings = $NetworkSettings + $NetAdapter.GetRelated("Msvm_GuestNetworkAdapterConfiguration")
        }
    }
 
    $NetworkSettings[0].IPAddresses = $IPAddress
    $NetworkSettings[0].Subnets = $Subnet
    $NetworkSettings[0].DefaultGateways = $DefaultGateway
    $NetworkSettings[0].DNSServers = $DNSServer
    $NetworkSettings[0].ProtocolIFType = 4096
 
    if ($dhcp) {
        $NetworkSettings[0].DHCPEnabled = $true
    } else {
        $NetworkSettings[0].DHCPEnabled = $false
    }
 
    $Service = Get-WmiObject -Class "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
    $setIP = $Service.SetGuestNetworkAdapterConfiguration($VM, $NetworkSettings[0].GetText(1))
 
    if ($setip.ReturnValue -eq 4096) {
        $job=[WMI]$setip.job 
 
        while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
            start-sleep 1
            $job=[WMI]$setip.job
        }
 
        if ($job.JobState -eq 7) {
            "Success update the TCP/IP configuration !"
        }
        else {
            $job.GetError()
        }
    } elseif($setip.ReturnValue -eq 0) {
            "Success update the TCP/IP configuration !"
    }
}

# function for setting the TCP/IP for the new VM NanoServer (static @IP)
Function DockerSwarmMSKitWithTLSAuthentication {

    param([String]$ServersInCluster,[String]$IPAddress,[String]$FirstVM,[String]$Subnet) 

if ($IPAddress -eq $FirstVM) {

" "
"All the Docker Engine hosts (client, swarm manager(s) and swarm workers) have a copy of the CA’s certificate as well as their own key-pair signed by the CA."
"TLS Authentication will be automatically set and configure between Docker, Swarm and Client :"
" "
"Create a Certificate Authority (CA) server, Create and sign keys for the Swarm Manager and Workers ... Please Wait ..."
" "

    $OpenSSLPath = "$global:VMPath\nanoserver-offine-temp\ProgramData\OpenSSL\bin"

    New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp\ProgramData\OpenSSL\TLS" -Force | Out-Null

    $KeyStoreTLS = "$global:VMPath\nanoserver-offine-temp\ProgramData\OpenSSL\TLS"


$LastOctetAdress = $IPAddress.Split('.')
$NextIP = [int]($LastOctetAdress[-1]) 

$j=2
$a =
    for($i = $NextIP; $i -lt ($NextIP+$ServersInCluster); $i++){
       "IP."+$j+" = $Subnet$i`r" 
        $j++
    } 

$opensslcnf = @" 
[ req ]
default_bits = 4096
default_keyfile = ca-priv-key.pem
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
default_md = sha1
string_mask = nombstr
req_extensions = v3_req
prompt = no

[req_distinguished_name]
countryName = FR
stateOrProvinceName = IdF
localityName = PARIS
organizationalUnitName = SwarmMSKit

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ v3_ca ]
subjectAltName = @alt_names
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ alt_names ]
# The IPs of the Docker and Swarm hosts
 IP.1 = 127.0.0.1
 $a
"@

    $opensslcnf | Out-File $KeyStoreTLS\openssl.cnf

    (Get-Content -path "$KeyStoreTLS\openssl.cnf" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$KeyStoreTLS\openssl.cnf"

    #New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp\certs.d" -Force | Out-Null
    New-Item -Type Directory -Path "$global:VMPath\nanoserver-offine-temp\ProgramData\docker\certs.d" -Force | Out-Host | Out-Null      
    
    " " 
    "$OpenSSLPath\openssl.exe -ArgumentList genrsa -out $KeyStoreTLS\ca-priv-key.pem 2048"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "genrsa -out $KeyStoreTLS\ca-priv-key.pem 2048" | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $KeyStoreTLS\ca-priv-key.pem
    
    
    " "
    "$OpenSSLPath\openssl.exe -ArgumentList req -config $KeyStoreTLS\openssl.cnf -new -key $KeyStoreTLS\ca-priv-key.pem -x509 -days 1825 -out $KeyStoreTLS\ca.pem"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "req -config $KeyStoreTLS\openssl.cnf -new -key $KeyStoreTLS\ca-priv-key.pem -x509 -days 1825 -out $KeyStoreTLS\ca.pem" | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $KeyStoreTLS\ca.pem
    
    
    if (!(Test-Path -Path "$env:USERPROFILE\.SwarmMSKit")) {" ";"Create $env:USERPROFILE\.SwarmMSKit folder and copy the certificates for connecting to a TLS-enabled daemon with TLS ... Please Wait ...";" "; 
        mkdir "$env:USERPROFILE\.SwarmMSKit" | Out-Host | Out-Null
    } else {
    
        Remove-Item -Recurse $env:USERPROFILE\.SwarmMSKit\* -Force
    
    }
    
    " "
    "$OpenSSLPath\openssl.exe -ArgumentList genrsa -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem 2048"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "genrsa -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem 2048"  | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem

    " "
    "$OpenSSLPath\openssl.exe -ArgumentList req -subj /CN=127.0.0.1 -new -key $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "req -subj ""/CN=127.0.0.1"" -new -key $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr"  | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr
    
    " "    
    "$OpenSSLPath\openssl.exe -ArgumentList x509 -req -days 1825 -in $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr -CA $KeyStoreTLS\ca.pem -CAkey $KeyStoreTLS\ca-priv-key.pem -CAcreateserial -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1-cert.pem -extensions v3_req -extfile $KeyStoreTLS\openssl.cnf"  
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "x509 -req -days 1825 -in $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr -CA $KeyStoreTLS\ca.pem -CAkey $KeyStoreTLS\ca-priv-key.pem -CAcreateserial -out $env:USERPROFILE\.SwarmMSKit\127.0.0.1-cert.pem -extensions v3_req -extfile $KeyStoreTLS\openssl.cnf"  | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $env:USERPROFILE\.SwarmMSKit\127.0.0.1-cert.pem
    " "

    Copy-Item -Path $KeyStoreTLS\ca.pem -Destination $env:USERPROFILE\.SwarmMSKit\ca.pem | Out-Host | Out-Null
    Rename-Item -Path $env:USERPROFILE\.SwarmMSKit\127.0.0.1-cert.pem -NewName $env:USERPROFILE\.SwarmMSKit\cert.pem | Out-Host | Out-Null
    Rename-Item -Path $env:USERPROFILE\.SwarmMSKit\127.0.0.1-priv-key.pem -NewName $env:USERPROFILE\.SwarmMSKit\key.pem | Out-Host | Out-Null
     
    " "
    "You have now a copy of the CA’s certificate as well as their own key-pair signed by the CA for executing Docker command on the Cluster Swarm with a TLS Authentication."
    "All the certificates are save in this folder : $env:USERPROFILE\.SwarmMSKit"
    " "
          
    $LastOctetAdress = $IPAddress.Split('.')
    $NextIP = [int]($LastOctetAdress[-1]) 

    for($i = $NextIP; $i -lt ($NextIP+$ServersInCluster); $i++){

    " "
    "$OpenSSLPath\openssl.exe -ArgumentList genrsa -out $KeyStoreTLS\$Subnet$i-priv-key.pem 2048"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "genrsa -out $KeyStoreTLS\$Subnet$i-priv-key.pem 2048" | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $KeyStoreTLS\$Subnet$i-priv-key.pem

    " "
    "$OpenSSLPath\openssl.exe -ArgumentList req -subj /CN=$Subnet$i -new -key $KeyStoreTLS\$Subnet$i-priv-key.pem -out $KeyStoreTLS\$Subnet$i.csr"
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "req -subj ""/CN=$Subnet$i"" -new -key $KeyStoreTLS\$Subnet$i-priv-key.pem -out $KeyStoreTLS\$Subnet$i.csr"  | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $KeyStoreTLS\$Subnet$i.csr
    
    " "    
    "$OpenSSLPath\openssl.exe -ArgumentList x509 -req -days 1825 -in $KeyStoreTLS\$Subnet$i.csr -CA $KeyStoreTLS\ca.pem -CAkey $KeyStoreTLS\ca-priv-key.pem -CAcreateserial -out $KeyStoreTLS\$Subnet$i-cert.pem -extensions v3_req -extfile $KeyStoreTLS\openssl.cnf"  
    Start-Process -FilePath "$OpenSSLPath\openssl.exe" -ArgumentList "x509 -req -days 1825 -in $KeyStoreTLS\$Subnet$i.csr -CA $KeyStoreTLS\ca.pem -CAkey $KeyStoreTLS\ca-priv-key.pem -CAcreateserial -out $KeyStoreTLS\$Subnet$i-cert.pem -extensions v3_req -extfile $KeyStoreTLS\openssl.cnf" | Out-Host | Out-Null
    Start-Sleep -Seconds 5
    " "
    gc $KeyStoreTLS\$Subnet$i-cert.pem
    " "

    if ((Test-Path -Path $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr)) {    
        Remove-Item -Path $env:USERPROFILE\.SwarmMSKit\127.0.0.1.csr -Force | Out-Null         
    } 
    
    ""
    "The Docker Engine host which have this [@IP:$Subnet$i] will have a copy of the CA’s certificate as well as their own key-pair signed by the CA."
    " "

    } 
} else {
    
    " "  
    "The Certifactes Generated for this [$IPAddress] NanoServer have been already generated/performed !"
    "Copying them and configuring them for the Daemon Docker Engine ... Please Wait ..."
    " "
}
    

}

Function SwarMSKit-Check {

    param([String]$IPAddress,[String]$SwarmClusterPort,[bool]$EnabledDockerDaemonTLS,[String]$Username,[String]$clearadminPassword) 

$TLSCertificatesPath = "$env:USERPROFILE\.SwarmMSKit"

if ($EnabledDockerDaemonTLS -eq "$True") {
    $TLSverify = "--tlsverify --tlscacert=$TLSCertificatesPath\ca.pem --tlscert=$TLSCertificatesPath\cert.pem --tlskey=$TLSCertificatesPath\key.pem" 
    } else {
    $TLSverify =""
}

    $Source = "\\$IPAddress\c$\Windows\System32"
    $Dest   = "$TLSCertificatesPath"
    
    if (!(Get-PSDrive S)) {
    
        $MapDrive ="net use S: $Source /user:$Username $clearadminPassword"
        Invoke-Expression $MapDrive | Out-Host | Out-Null     
    }
    else { 
    
        
        $MapDriveDelete ="net use S: /delete"
        Invoke-Expression $MapDriveDelete | Out-Host | Out-Null
        $MapDrive ="net use S: $Source /user:$Username $clearadminPassword"
        Invoke-Expression $MapDrive | Out-Host | Out-Null 
    
    }
        
    Copy-Item -Path S:\vault.exe -Destination $Dest\vault.exe
    Copy-Item -Path S:\consul.exe -Destination $Dest\consul.exe 


$batchTestPostSwarMSKitInstallation = "@
@echo off
echo.
echo @@@@@     SwarmMSKit has been deployed ! Let's verify it :) !     @@@@@
echo.
pause
echo.
echo.
echo *****     CONSUL SERVER STATUS :
echo.
$TLSCertificatesPath\consul members -rpc-addr=$IPAddress`:8400
echo.
pause
echo.
echo *****     VAULT SERVER STATUS :
echo.
$TLSCertificatesPath\vault status
echo.
pause
echo.
echo *****     SWARM CLUSTER STATUS :
echo.
docker -H tcp://$IPAddress`:$SwarmClusterPort $TLSverify info 
echo.
pause
echo.
echo *****     RUN A CONTAINER IN THE CLUSTER SWARM (nanoserver cmd)  :
echo.
echo command will be launch is :   docker -H tcp://$IPAddress`:$SwarmClusterPort $TLSverify run -it nanoserver cmd
echo.
pause
docker -H tcp://$IPAddress`:$SwarmClusterPort $TLSverify run -it nanoserver cmd
echo.
echo.
echo.
echo. Thank you for using SwarmMSKit and stay tuned for the next update/add ...
echo.
echo.
pause
echo.
@"

    $batchTestPostSwarMSKitInstallation | Out-File $env:USERPROFILE\Desktop\SwarmMSKIT-Check.cmd

    (Get-Content -path "$env:USERPROFILE\Desktop\SwarmMSKIT-Check.cmd" -Encoding Unicode) | Set-Content -Encoding "Default" -Path "$env:USERPROFILE\Desktop\SwarmMSKIT-Check.cmd"

    Start-Process -FilePath http://$IPAddress`:9000
    Start-Process -FilePath http://$IPAddress`:8081
    
    Start-Process -FilePath "$env:USERPROFILE\Desktop\SwarmMSKIT-Check.cmd"

}
