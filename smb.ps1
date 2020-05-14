#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1

function Set-SMBSecOpts
{
    if ($__SMB__ -eq $True) 
    { 
        Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force 
        
        # Allow File and printer sharing
        & netsh.exe advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    }
    else 
    { 
        Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force 
        # Block File and printer sharing
        & netsh.exe advfirewall firewall set rule group="File and Printer Sharing" new enable=No
    }

    <#
    
                SERVER SETTINGS
    
    #>

    #Set the hardening level to 2
    Set-SmbServerConfiguration -SmbServerNameHardeningLevel 2 -Force

    #Dont announce the SMB server (security by obscurity)
    Set-SmbServerConfiguration -AnnounceServer $False -Force

    #Audit SMBv1. Even though its disabled, this will catch intruders should it be re-enabled.
    Set-SmbServerConfiguration -AuditSmb1Access $True -Force

    #Disable the default server share
    Set-SmbServerConfiguration -AutoShareServer $False -Force

    #Disable the default workstation share
    Set-SmbServerConfiguration -AutoShareWorkstation $False -Force

    #Set max open cached files to 32
    Set-SmbServerConfiguration -CachedOpenLimit 32 -Force

    #Enable authenticate user sharing
    Set-SmbServerConfiguration -EnableAuthenticateUserSharing $True -Force

    #Enable forced logoff
    Set-SmbServerConfiguration -EnableForcedLogoff $True -Force

    #Disable leasing (smbv1)
    Set-SmbServerConfiguration -EnableLeasing $False -Force

    #Enable multichannel
    Set-SmbServerConfiguration -EnableMultiChannel $True -Force

    #Enable Oplocks
    Set-SmbServerConfiguration -EnableOplocks $True -Force

    #Disable SMBV1
    Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

    #Enable security signing
    Set-SmbServerConfiguration -EnableSecuritySignature $True -Force

    #Enable strict name checking
    Set-SmbServerConfiguration -EnableStrictNameChecking $True -Force

    #Encrypt data
    Set-SmbServerConfiguration -EncryptData $True -Force

    #Max channels per session
    Set-SmbServerConfiguration -MaxChannelPerSession 2 -Force

    #Max outgoing commands per session
    Set-SmbServerConfiguration -MaxMpxCount 16 -Force

    #Only one session per connection
    Set-SmbServerConfiguration -MaxSessionPerConnection 1 -Force

    #Max smbv1 work items
    Set-SmbServerConfiguration -MaxWorkItems 16 -Force

    #Clear null session pipes
    Set-SmbServerConfiguration -NullSessionPipes "" -Force

    #Clear anonymous session shares
    Set-SmbServerConfiguration -NullSessionShares $SMB_AnonymousSharesList -Force

    #Set pending client timeout to 16 seconds to prevent a denial of service scenario
    Set-SmbServerConfiguration -PendingClientTimeoutInSeconds 16 -Force

    #Dont allow exceptions to our encryption requirements. Breaks compatibility with smbv1.
    Set-SmbServerConfiguration -RejectUnencryptedAccess $True -Force

    #Require our security signing
    Set-SmbServerConfiguration -RequireSecuritySignature $True -Force

    #Hide the server
    Set-SmbServerConfiguration -ServerHidden $True -Force

    #Set SMB credits to defaults
    Set-SmbServerConfiguration -Smb2CreditsMax 512 -Force
    Set-SmbServerConfiguration -Smb2CreditsMin 8192 -Force

    #Set the smb host to be the stable storage
    Set-SmbServerConfiguration -TreatHostAsStableStorage $True -Force

    #Enable circular name validation
    Set-SmbServerConfiguration -ValidateAliasNotCircular $True -Force

    #Validate the scope of the share upon creation
    Set-SmbServerConfiguration -ValidateShareScope $True -Force

    #Validate the share scope is not aliased
    Set-SmbServerConfiguration -ValidateShareScopeNotAliased $True -Force

    #Validate the target name upon creation
    Set-SmbServerConfiguration -ValidateTargetName $True -Force

    <#
    
                CLIENT SETTINGS
    
    #>

    #Enable bandwidth throttling (CLIENT)
    Set-SmbClientConfiguration -EnableBandwidthThrottling $True -Force

    #Enable byte range locking (CLIENT)
    Set-SmbClientConfiguration -EnableByteRangeLockingOnReadOnlyFiles $True -Force

    #Disable insecure guest logons (CLIENT)
    Set-SmbClientConfiguration -EnableInsecureGuestLogons $False -Force

    #Enable multi-channel optimizations (CLIENT)
    Set-SmbClientConfiguration -EnableMultiChannel $True -Force

    #Enable security signature (CLIENT)
    Set-SmbClientConfiguration -EnableSecuritySignature $True -Force

    #Enable oplocks (CLIENT)
    Set-SmbClientConfiguration -OplocksDisabled $False -Force

    #Require a security signature (CLIENT)
    Set-SmbClientConfiguration -RequireSecuritySignature $True -Force

    #Enable oplocks (CLIENT)
    Set-SmbClientConfiguration -UseOpportunisticLocking $True -Force


    <#
    
                SHARE SETTINGS
    
    #>

    $smbshares = Get-SmbShare;

    Foreach ($share in $smbshares)
    {
        #Force the ACLs of the folder this is over to match this share's acls
        Set-SmbPathAcl -ShareName $share.Name

        #Disable offline caching for the share
        Set-SmbShare -Name $share.Name -CachingMode None -Force

        #Set the max users for the share
        Set-SmbShare -Name $share.Name -ConcurrentUserLimit 8 -Force

        #Disable offline caching for the share
        Set-SmbShare -Name $share.Name -ContinuouslyAvailable $False -Force

        #Force encrypting data for the share
        Set-SmbShare -Name $share.Name -EncryptData $True -Force

        #Force folder enumerations to accept ACL rules
        Set-SmbShare -Name $share.Name -FolderEnumerationMode AccessBased -Force

        #Set the description for the share to signify the share being secured
        Set-SmbShare -Name $share.Name -Description "Share secured!" -Force
    }

    if ($__SMB__ -eq $True) 
    { 
        Set-Service -Name LanmanServer -StartupType Automatic
        Restart-Service -Name LanmanServer -Force
    }
    else
    {
        Set-Service -Name LanmanServer -StartupType Disabled
        Stop-Service -Name LanmanServer -Force -NoWait
    }

    if ($__SMB__ -eq $True)
    {
        Add-Content -Path ".\Checklist\SMB.txt" -Force -Value "1.) Check to make sure that only valid shared folders exist. Ignore ipc$, admin$, c$"
        Add-Content -Path ".\Checklist\SMB.txt" -Force -Value "2.) Check security permissions on shared folders and make sure they make sense. Double check your lists."
        Add-Content -Path ".\Checklist\SMB.txt" -Force -Value "Note: To access shared folders, WIN+R, fsmgmt.msc. Here is a list of shares: "
        $shares = $(Get-SmbShare)
        Foreach ($sh in $shares)
        {
            Add-Content -Path ".\Checklist\SMB.txt" -Force -Value $sh.Name
        }
        Start-Process -FilePath notepad.exe -ArgumentList ".\Checklist\SMB.txt"
    }
}

try { Set-SMBSecOpts; } catch { Write-Error $_; }