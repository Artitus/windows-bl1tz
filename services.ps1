#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

#Enable/Disable windows features
function Set-WinFeatures
{
    #Disable the telnet client
    Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -Remove -NoRestart -LogLevel 1

    #Disable Trivial File Transfer Protocol (UDP ftp, limited, unsecure)
    Disable-WindowsOptionalFeature -Online -FeatureName "TFTP" -Remove -NoRestart -LogLevel 1

    #Disable Legacy Components
    Disable-WindowsOptionalFeature -Online -FeatureName "LegacyComponents" -Remove -NoRestart -LogLevel 1

    #Disable DirectPlay
    Disable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -Remove -NoRestart -LogLevel 1

    #Disable SimpleTCP
    Disable-WindowsOptionalFeature -Online -FeatureName "SimpleTCP" -Remove -NoRestart -LogLevel 1

    #Disable MSMQ-Server
    Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Server" -Remove -NoRestart -LogLevel 1

    #Disable windows media player
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -Remove -NoRestart -LogLevel 1

    #Disable and remove MicrosoftWindowsPowerShellV2
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -Remove -NoRestart -LogLevel 1

    #Enable Windows-Defender-Default-Definitions
    Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Default-Definitions" -NoRestart -All

    #Disable Microsoft-Windows-Subsystem-Linux
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -Remove -NoRestart -LogLevel 1

    if ($global:ScriptPlatform -eq "win16")
    {
        #Disable iSCSI Powershell
        Uninstall-WindowsFeature -Name "iSCSITargetServer-PowerShell" -Remove

        #Disable WindowsPowerShellWebAccess
        Uninstall-WindowsFeature -Name "WindowsPowerShellWebAccess" -Remove

        #Disable RemoteAccessServer
        Uninstall-WindowsFeature -Name "RemoteAccessServer" -Remove

        #Disable WebAccess
        Uninstall-WindowsFeature -Name "WebAccess" -Remove

        #Disable Server-RSAT-SNMP
        Uninstall-WindowsFeature -Name "Server-RSAT-SNMP" -Remove

        #Disable BitLocker Network unlocking
        Uninstall-WindowsFeature -Name "BitLocker-NetworkUnlock" -Remove
        
        #Disable Fax role
        Uninstall-WindowsFeature -Name "FaxServiceRole" -Remove

        #Enable Windows Defender
        Install-WindowsFeature -Name "Windows-Defender-Gui"

        #Install Bitlocker
        Install-WindowsFeature -Name "BitLocker"

        #Enable Windows Defender Features
        Install-WindowsFeature -Name "Windows-Defender-Features"
    }
}

function Set-SecuredServices
{
    # Fire and Forget Bad services
    & cmd.exe /c 'sc stop tlntsvr'
    & cmd.exe /c 'sc config tlntsvr start= disabled'
    & cmd.exe /c 'sc stop snmptrap'
    & cmd.exe /c 'sc config snmptrap start= disabled'
    & cmd.exe /c 'sc stop ssdpsrv'
    & cmd.exe /c 'sc config ssdpsrv start= disabled'
    & cmd.exe /c 'sc stop remoteregistry'
    & cmd.exe /c 'sc config remoteregistry start= disabled'
    & cmd.exe /c 'sc stop Messenger'
    & cmd.exe /c 'sc config Messenger start= disabled'
    & cmd.exe /c 'sc stop upnphos'
    & cmd.exe /c 'sc config upnphos start= disabled'
    & cmd.exe /c 'sc stop NetTcpPortSharing'
    & cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
    & cmd.exe /c 'sc stop RRAS'
    & cmd.exe /c 'sc config RRAS start= disabled'
    & cmd.exe /c 'sc stop Telephony'
    & cmd.exe /c 'sc config Telephony start= disabled'
    & cmd.exe /c 'sc stop fax'
    & cmd.exe /c 'sc config fax start= disabled'
    & cmd.exe /c 'sc stop fax'
    & cmd.exe /c 'sc config fax start= disabled'

    # Manual
    & cmd.exe /c 'sc stop simptcp'
    & cmd.exe /c 'sc config simptcp start= Manual'
    

    # Fire and Forget Good services
    & cmd.exe /c 'sc start wuauserv'
    & cmd.exe /c 'sc config wuauserv start= auto'
    & cmd.exe /c 'sc start EventLog'
    & cmd.exe /c 'sc config EventLog start= auto'
    & cmd.exe /c 'sc start MpsSvc'
    & cmd.exe /c 'sc config MpsSvc start= auto'
    & cmd.exe /c 'sc start WinDefend'
    & cmd.exe /c 'sc config WinDefend start= auto'
    & cmd.exe /c 'sc start WdNisSvc'
    & cmd.exe /c 'sc config WdNisSvc start= auto'
    & cmd.exe /c 'sc start Sense'
    & cmd.exe /c 'sc config Sense start= auto'
    & cmd.exe /c 'sc start Schedule'
    & cmd.exe /c 'sc config Schedule start= auto'
    & cmd.exe /c 'sc start SCardSvr'
    & cmd.exe /c 'sc config SCardSvr start= auto'
    & cmd.exe /c 'sc start ScDeviceEnum'
    & cmd.exe /c 'sc config ScDeviceEnum start= auto'
    & cmd.exe /c 'sc start SCPolicySvc'
    & cmd.exe /c 'sc config SCPolicySvc start= auto'
    & cmd.exe /c 'sc start wscsvc'
    & cmd.exe /c 'sc config wscsvc start= auto'
    & cmd.exe /c 'sc start napagent'
    & cmd.exe /c 'sc config napagent start= auto'
    

    # Other Services

    #IP Sharing
    Stop-Service -Name "SharedAccess" -Force -NoWait
    Set-Service -Name "SharedAccess" -StartupType Disabled -ErrorAction SilentlyContinue

    #Windows Media Player NetSharing
    Stop-Service -Name "WMPNetworkSvc" -Force -NoWait
    Set-Service -Name "WMPNetworkSvc" -StartupType Disabled -ErrorAction SilentlyContinue

    #Set these two services to manual startup
    $ManualServices = @("wersvc", "wecsvc")
    foreach ($ManualService in $ManualServices)
    {
        Set-Service $ManualService -StartupType Manual -ErrorAction SilentlyContinue
    }


    # Fix all sorts of weird vulnerabilities with service and program paths
    & .\Programs\fixservices.ps1 -FixServices -FixUninstall -FixEnv
}


try { Set-WinFeatures } catch { Write-Error $_; }