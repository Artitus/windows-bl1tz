#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1
function Set-RDPSecOpts
{
    if ($__RDP__ -eq $True) 
    { 
        #Enable remote desktop
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0 -Force

        #Enable remote desktop
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value 0 -Force

        #Force highest TLS
        Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "MinEncryptionLevel" -Value 4 -Force

        #Allow remote desktop through the firewall
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

        #Set remote desktop service startup to manual
        Set-Service -Name TermService -StartupType Manual

        #Restart remote desktop service
        Restart-Service -Name TermService -Force

        #Enable remote assistance
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fAllowToGetHelp" -Value 1 -Force

        #Enable remote assistance firewall rules
        Enable-NetFirewallRule -DisplayGroup "Remote Assistance"
        
    }
    else 
    { 
        #Disable remote desktop
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 1 -Force
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value 1 -Force
        
        #Disable remote desktop firewall rule
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

        #Set remote desktop service startup to disabled
        Set-Service -Name TermService -StartupType Disabled

        #Stop remote desktop service
        Stop-Service -Name TermService -Force -NoWait

        #Disable remote assistance
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fAllowToGetHelp" -Value 0 -Force

        if ($ScriptPlatform -eq "win16")
        {
            #Disable RemoteAccess
            Uninstall-WindowsFeature -Name "RemoteAccess" -Remove

            #Disable RemoteAccessServer
            Uninstall-WindowsFeature -Name "RemoteAccessServer" -Remove
        }

        #Disable remote assistance firewall rule
        Disable-NetFirewallRule -DisplayGroup "Remote Assistance"
    }

    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value $RDP_Port -Force

    #Force extended auth
    (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)

    if ($__RDP__ -eq $True)
    {
        New-Item -Path ".\Checklist\REMOTEDESKTOP.txt" -Force
        Add-Content -Path ".\Checklist\REMOTEDESKTOP.txt" -Force -Value "1.) Check to make sure that only valid users are in the Remote Desktop Users group. (lusrmgr.msc)"
        Add-Content -Path ".\Checklist\REMOTEDESKTOP.txt" -Force -Value "2.) Check remote desktop firewall ports and enable encrypted connections. You should see a lock icon on the rule."
        Add-Content -Path ".\Checklist\REMOTEDESKTOP.txt" -Force -Value "3.) If you lose points for remote desktop being disabled, but you check and see that it is enabled, run Programs/FixRDP.bat as administrator"
        Add-Content -Path ".\Checklist\REMOTEDESKTOP.txt" -Force -Value "Note: You can access the remote desktop configuration with WIN+R, sysdm.cpl"
        Start-Process -FilePath notepad.exe -ArgumentList ".\Checklist\REMOTEDESKTOP.txt"
    }
}

try { Set-RDPSecOpts; } catch { Write-Error $_; }