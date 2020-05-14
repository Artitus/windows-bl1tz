#requires -version 4.0
#requires -runasadministrator
# Must exist at the header of every single executable script!
. .\__config.ps1

$Scripts = @(
    ".\users.ps1",
    ".\programs.ps1",
    ".\smb.ps1",
    ".\rdp.ps1",
    ".\firewall.ps1",
    ".\dns.ps1",
    ".\services.ps1",
    ".\ftp.ps1",
    ".\misc.ps1",
    ".\files.ps1",
    ".\firefox.ps1",
    ".\iis.ps1"
);

function Get-Points
{
    $Proceed = Read-Host "Was this script executed intentionally? (Y/N)";

    $AllJobs = Get-Job

    if ($Proceed -ne "Y" -and $Proceed -ne "y") { return; } # Prevents accidental shells during development

    if (-NOT $global:ScriptConfigured -eq $True) { Write-Host "You havent configured the script. You cannot run an unconfigured script."; return; }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value $global:CachedUsername
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value $global:UserCommonPassword
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value "1"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceAutoLogon -Value "1"

    Write-Host "Starting updates...";

    USOClient.exe ScanInstallWait
    USOClient.exe StartInstall
    
    $ScriptPath = [string]$(Get-Location);

    # Execute every script in the scripts list async
    Foreach ($Script in $Scripts)
    { 
        try
        {
            Start-Job -name $Script -FilePath $Script -ArgumentList $Script, $ScriptPath
        }
        catch { }
    }

    $AllJobs = Get-Job

    # Wait for all active jobs to exit. We dont want to import group policy until the end of our script.
    Wait-InvokedJobs

    Foreach ($Job in $AllJobs)
    {
        $ReceivedJob = $(Receive-Job -Job $Job -AutoRemoveJob)
        New-Item -Path (".\Logs\" + $Job.Name + ".log") -Force
        Add-Content -Path (".\Logs\" + $Job.Name + ".log") -Force -Value $ReceivedJob
    }

    if ($global:ActiveDirectory)
    {
        #Import active directory policies
        Import-Module GroupPolicy
        Import-GPO -BackupID "{F6A5DB3D-427D-4424-9C0C-7057A6F329FE}" -TargetName "Default Domain Controller" -Path ".\GPO\WinADGPO" -CreateIfNeeded
        Import-GPO -BackupID "{F6A5DB3D-427D-4424-9C0C-7057A6F329FE}" -TargetGuid "Default Domain" -Path ".\GPO\WinADGPO" -CreateIfNeeded
    }

    # Import local group policy
    & ".\Programs\LGPO.exe" '/g' ".\GPO\WinMasterGPO"
    & ".\Programs\LGPO.exe" '/a' ".\GPO\WinMasterGPO\winaudit.csv"
    & gpupdate.exe /force
    
    Write-Host "Group policy imported, applying now, then applying final registry values."
    Start-Sleep -Seconds 15

    Set-ExtraReg
    
    # Import WMI backup configuration properties
    & WinMgmt.exe '/restore' ".\Data\wmi-conf.rec" '1'
    
    Write-Host -ForegroundColor Green 'A computer restart is required to apply settings. Restart computer now?'
    Restart-Computer -Force -Confirm
}

function Set-ExtraReg
{
    # Clear memory pagefile. Group policy is wrong.
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Force

    # Prevent ICMP OSPF override
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "EnableICMPRedirect" -Value 0 -Force

    # Prevent SYN Denial of Service
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "SynAttackProtect" -Value 1 -Force

    # Stop attacker from forcing tiny MTU (DoS)
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "EnablePMTUDiscovery" -Value 0 -Force

    # TCP Keep alive time
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "KeepAliveTime" -Value 300000 -Force

    # DisableIPSourceRouting
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "DisableIPSourceRouting" -Value 2 -Force

    # TcpMaxDataRetransmissions
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name "TcpMaxDataRetransmissions" -Value 3 -Force

    # Disable fs creating 8.3 naming (exploited many times)
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\FileSystem\" -Name "NtfsDisable8dot3NameCreation" -Value 1 -Force

    # Block non admins from entering safemode
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "SafeModeBlockNonAdmins" -Value 1 -Force
    Set-ItemProperty "HKLM:\SOFTWARE\WoW6432Node\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "SafeModeBlockNonAdmins" -Value 1 -Force

    # Enable EFS
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableEncryption" -Value 0 -Force

    # Action center
    Set-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 0 -Force

    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "AutoRun" -Value "" -Force

    #Set all event log types to reject guess access
    $Keys = $(Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog");
    
    Foreach ($key in $Keys)
    {
        $key | Set-ItemProperty -Name RestrictGuestAccess -Value 1 -Force
    }

    $SecureString = ConvertTo-SecureString "1234567890" -AsPlainText -Force
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector

    & '.\Programs\regjump.exe' 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\'

    # Disable remote management
    Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Name EnableRemoteManagement -Value 0 -Force
}

function Wait-InvokedJobs
{ 
    $JobsLaunch = Get-Date
    do
    { 
        Clear-Host 
 
        $myjobs = Get-Job  
        $myjobs | Out-File $env:TEMP\scrapjobs.txt 
        Get-Content $env:TEMP\scrapjobs.txt 
        $jobscount = $myjobs.Count 
        "$jobscount jobs running" 
        
        $done = 0 
 
        foreach ($job in $myjobs)
        { 
 
            $mystate = $job.State 
            if ($mystate -eq "Completed") { $done = $done + 1 } 
 
        } 
        "$done jobs done" 
 
        " 
" 
        $currentTime = Get-Date 
        "Jobs started at $JobsLaunch" 
        "Current time $currentTime  " 
 
        $timecount = $currentTime - $JobsLaunch
        $timecount = $timecount.TotalMinutes 
        "Elapsed time in minutes $timecount" 
        Start-Sleep 5 
        Clear-Host 
    } while ( $done -lt $jobscount ) 
}

Get-Points;