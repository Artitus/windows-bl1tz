#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Limit-LocalIdiots
{
    # Get all local users
    $lusrs = Get-LocalUser
    $adm = $(Get-LocalUser | Where-Object { $_.SID -match '^S-1-5-.*-500$' });
    $gst = $(Get-LocalUser | Where-Object { $_.SID -match '^S-1-5-.*-501$' });

    # Foreach local user
    Foreach ($lusr in $lusrs)
    {
        # If its a builtin, skip it
        if ($adm.Name -eq $lusr.Name) { continue; }
        if ($gst.Name -eq $lusr.Name) { continue; }
        
        # Otherwise, Limit the local user
        Limit-LocalUser -UserObject $lusr
    }

    try { Remove-Item -Path "C:\Users\Default" -Force -Recurse } catch { }

    # Limit the local administrator account
    Limit-BuiltinUser -UserObject $adm

    # Limit the local guest account
    Limit-BuiltinUser -UserObject $gst

    # Limit the groups that the guest is part of (should be none)
    Limit-GuestGroups
}

function Limit-GuestGroups
{
    # Get all groups
    $groups = Get-LocalGroup
    Foreach ($group in $groups)
    {
        # Purge the guest account from all groups
        Remove-LocalGroupMember -Group $group -Member $gst
    }
}

function Limit-ADIdiots
{
    $GlobalIdiots = $(Get-ADUser -Filter *);
    $Admin = $(Get-ADUser -Filter * | Where-Object { $_.SID -match '^S-1-5-.*-500$' });
    $Guest = $(Get-ADUser -Filter * | Where-Object { $_.SID -match '^S-1-5-.*-501$' });
    $krberos = $(Get-ADUser -Filter * | Where-Object { $_.SID -match '^S-1-5-.*-502$' });
    Foreach ($idiot in $GlobalIdiots)
    {
        if ($idiot -eq $Admin -or $idiot -eq $Guest -or $idiot -eq $krberos)
        {
            $idiot | Set-ADUser -CannotChangePassword 1
            $idiot | Set-ADUser -Enabled $false
            $idiot | Set-ADUser -PasswordNeverExpires 1
            if ($idiot -eq $Admin)
            {
                $idiot | Set-ADUser -SamAccountName "bl1tzedadm"
                $idiot | Set-ADUser -AccountNotDelegated $true
                
            }
            elseif ($idiot -eq $Guest)
            {
                $idiot | Set-ADUser -SamAccountName "bl1tzedgst"
                $idiot | Set-ADUser -AccountNotDelegated $true
            }
        }
        else
        {
            $idiot | Set-ADUser -CannotChangePassword 0
            $idiot | Set-ADUser -ChangePasswordAtLogon 1
            $idiot | Set-ADUser -PasswordNeverExpires 0
            $idiot | Set-ADUser -AccountNotDelegated $true
        }
        $idiot | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $global:UserCommonPassword -Force)
        $idiot | Set-ADUser -AccountExpirationDate 0 
        $idiot | Set-ADUser -AllowReversiblePasswordEncryption $false 
        $idiot | Set-ADUser -Description "bl1tzed active directory idiot"
        $idiot | Set-ADUser -KerberosEncryptionType AES256
        $idiot | Set-ADUser -City "no"
        $idiot | Set-ADUser -Company "yo"
        $idiot | Set-ADUser -Country "merica"
        $idiot | Set-ADUser -Department "infosec"
        $idiot | Set-ADUser -EmailAddress "t1security@oi.net"
        $idiot | Set-ADUser -EmployeeID "6969"
        $idiot | Set-ADUser -EmployeeNumber "6969"
        $idiot | Set-ADUser -Fax "dont fax me"
        $idiot | Set-ADUser -HomePage "www.google.com"
        $idiot | Set-ADUser -HomePhone "8675309"
        $idiot | Set-ADUser -Initials "LOL"
        $idiot | Set-ADUser -MobilePhone "oi"
        $idiot | Set-ADUser -Office "yike"
        $idiot | Set-ADUser -OfficePhone "oi"
        $idiot | Set-ADUser -Organization "oi"
        $idiot | Set-ADUser -POBox "POS"
        $idiot | Set-ADUser -PasswordNotRequired 0
        $idiot | Set-ADUser -PostalCode "1234"
        $idiot | Set-ADUser -ScriptPath ""
        $idiot | Set-ADUser -SmartcardLogonRequired 0
        $idiot | Set-ADUser -State "1234"
        $idiot | Set-ADUser -StreetAddress "1234 street"
        $idiot | Set-ADUser -Title "1234"
        $idiot | Unlock-ADAccount
    }
    Get-ADDomain -Current LocalComputer | Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true -LockoutDuration 0.0:30:00.0 -LockoutObservationWindow 0.0:15:00.0 -LockoutThreshold 5
    Get-ADDomain -Current LocalComputer | Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 30.0:00:00.0 -MinPasswordAge 1.0:00:00.0 -MinPasswordLength 12 -PasswordHistoryCount 12 -ReversibleEncryptionEnabled $false

    $serviceidiots = $(Get-ADComputerServiceAccount);
    foreach ($sidiot in $serviceidiots)
    {
        $sidiot | Set-ADServiceAccount -AccountExpirationDate 0
        $sidiot | Set-ADServiceAccount -KerberosEncryptionType AES256
        $sidiot | Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword @()
    }
}


function Limit-LocalUser
{
    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $UserObject
    )

    # Limit the user's home folder
    Limit-UserFolder -UserName $UserObject.Name

    $UserObject | Set-LocalUser -AccountNeverExpires
    $UserObject | Set-LocalUser -Password $global:UserCommonPassword
    $UserObject | Set-LocalUser -PasswordNeverExpires $false
    $UserObject | Set-LocalUser -UserMayChangePassword $true

    # Limit changes to the current user
    if ($UserObject.Name -eq $global:CurrentUser) { return; }
}

function Limit-UserFolder
{
    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]
        $UserName
    )

    if ($global:ClearHomeDirectories -eq $true)
    {
        if (Test-Path -Path "C:\Users\$UserName")
        {
            if ($UserName -ne $env:USERNAME)
            {
                try { Remove-Item -Path "C:\Users\$UserName\Desktop" -Force -Recurse } catch { }
                try { Remove-Item -Path "C:\Users\$UserName\AppData" -Force -Recurse } catch { }
                #   Enable EFS for all non current users
                Get-Item "C:\Users\$UserName" | Enable-FileEncryption
            }
            Remove-Item -Path "C:\Users\$UserName\Downloads" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Documents" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Links" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Music" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Pictures" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Roaming" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Saved Games" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\Videos" -Force -Recurse
            Remove-Item -Path "C:\Users\$UserName\*.*" -Force
        }
    }
}

function Limit-UserRelatedSettings
{
    #Disable media sharing
    #Clear the 'default Guests group' (SID S-1-5-32-546)

    #https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard
}

function Limit-BuiltinUser
{
    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $UserObject
    )

    # Disable the builtin
    $UserObject | Disable-LocalUser

    # Set the account to never expire
    Set-LocalUser -InputObject $UserObject -AccountNeverExpires

    # Set the description of the account to show it was blitzed
    Set-LocalUser -InputObject $UserObject -Description "Blitzed builtin account!"

    # Set the password on the account
    Set-LocalUser -InputObject $UserObject -Password $global:UserCommonPassword

    # Set the password to never expire
    Set-LocalUser -InputObject $UserObject -PasswordNeverExpires $true

    # Disable changing the password
    Set-LocalUser -InputObject $UserObject -UserMayChangePassword $false
}

try { Limit-LocalIdiots; } catch { Write-Error $_; }
try { if ($global:ActiveDirectory) { Limit-ADIdiots; } } catch { Write-Error $_; }
try { Limit-UserRelatedSettings; } catch { Write-Error $_; }