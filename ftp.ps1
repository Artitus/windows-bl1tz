#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1

#Note: Most FTP security must be done by hand.

$appcmd = $(Join-Path $env:windir 'system32\inetsrv\appcmd.exe')

function Set-FTPSecurity
{
    if ($global:__FTP__)
    {
        #Enable FTP Server
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -NoRestart -All
        
        #Enable FTP Service
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPSvc" -NoRestart -All
        
        #Enable FTP Extensibility
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPExtensibility" -NoRestart -All

        #Enable FTP firewall rule
        Enable-NetFirewallRule -DisplayGroup "FTP Server"

        & cmd.exe /c 'sc stop dism'
        & cmd.exe /c 'sc config dism start= disabled'

        #6.1 (L1) Ensure FTP requests are encrypted (Not Scored)
        & $appcmd 'set' 'config' '-section:system.applicationHost/sites' '/siteDefaults.ftpServer.security.ssl.controlChannelPolicy:"SslRequire"' '/siteDefaults.ftpServer.security.ssl.dataChannelPolicy:"SslRequire"' '/commit:apphost'

        #6.2 (L1) Ensure FTP Logon attempt restrictions is enabled (Not Scored)
        & $appcmd 'set' 'config' '-section:system.ftpServer/security/authentication' '/denyByFailure.enabled:"True"' '/commit:apphost'
    
        New-Item -Path ".\Checklist\FTP.txt" -Force
        Add-Content -Path ".\Checklist\FTP.txt" -Force -Value "1.) Open the IIS manager and edit the FTP site"
        Add-Content -Path ".\Checklist\FTP.txt" -Force -Value "2.) Set all the settings on your checklist, and use the screenshots taken of the configuration"
        Start-Process -FilePath notepad.exe -ArgumentList ".\Checklist\FTP.txt"
    
    }
    else
    {
        #Disable and remove FTP Service
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPSvc" -Remove -NoRestart -LogLevel 1

        #Disable and remove FTP Extensibility
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPExtensibility" -Remove -NoRestart -LogLevel 1

        #Disable and remove FTP Server
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove -NoRestart -LogLevel 1

        #Disable FTP firewall rule
        Disable-NetFirewallRule -DisplayGroup "FTP server"
    }
    
}

try { Set-FTPSecurity; } catch { Write-Error $_; }