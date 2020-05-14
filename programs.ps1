#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Limit-AppLockerPerms
{
    # TODO APPLOCKER
    #https://github.com/nsacyber/AppLocker-Guidance
}

function Add-PathVariable
{
    param (
        [string]$addPath
    )
    if (Test-Path $addPath)
    {
        $regexAddPath = [regex]::Escape($addPath)
        $arrPath = $env:Path -split ';' | Where-Object { $_ -notMatch 
            "^$regexAddPath\\?" }
        $env:Path = ($arrPath + $addPath) -join ';'
    }
    else
    {
        Throw "'$addPath' is not a valid path."
    }
}

function Add-ExtraTools
{
    $choco = [string]$(Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "chocolatey\bin");
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Add-PathVariable -addPath $choco
    $choco = $choco + "\choco.exe";
    & $choco feature enable -n allowGlobalConfirmation
    & $choco feature enable -n useFipsCompliantChecksums

    

    Foreach ($pkg in $global:RequiredPrograms)
    {
        & $choco install $pkg '--ignorechecksum' '--force' '-y'
    }

    try { Import-FireFoxConf } catch { }

    <#hcr#>

    & $choco upgrade all
}

function Import-FireFoxConf
{
    # Copy the configuration to x86 and x64
    if (Test-Path -Path "C:\Program Files (x86)\Mozilla Firefox\defaults\pref\")
    { Copy-Item -Item -Force -Path ".\Data\firefox\local-settings.js" -Destination "C:\Program Files (x86)\Mozilla Firefox\defaults\pref\" }

    if (Test-Path -Path "C:\Program Files\Mozilla Firefox\defaults\pref\")
    { Copy-Item -Force -Path ".\Data\firefox\local-settings.js" -Destination "C:\Program Files\Mozilla Firefox\defaults\pref\" }

    if (Test-Path -Path "C:\Program Files (x86)\Mozilla Firefox\")
    { Copy-Item -Force -Path ".\Data\firefox\mozilla.cfg" -Destination "C:\Program Files (x86)\Mozilla Firefox\" }

    if (Test-Path -Path "C:\Program Files\Mozilla Firefox\")
    { Copy-Item -Force -Path ".\Data\firefox\mozilla.cfg" -Destination "C:\Program Files\Mozilla Firefox\" }

    #Restart firefox
    Stop-Process -Name "firefox.exe" -Force
    if (Test-Path -Path "C:\Program Files\Mozilla Firefox\firefox.exe")
    {
        Start-Process -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe"
    }
    else 
    {
        Start-Process -FilePath "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    }
}

function Import-ThunderConf
{
    # Copy the configuration to x86 and x64
    if (Test-Path -Path "C:\Program Files (x86)\Mozilla Thunderbird\defaults\pref\")
    { Copy-Item -Item -Force -Path ".\Data\Thunderbird\local-settings.js" -Destination "C:\Program Files (x86)\Mozilla Thunderbird\defaults\pref\" }

    if (Test-Path -Path "C:\Program Files\Mozilla Thunderbird\defaults\pref\")
    { Copy-Item -Force -Path ".\Data\Thunderbird\local-settings.js" -Destination "C:\Program Files\Mozilla Thunderbird\defaults\pref\" }

    if (Test-Path -Path "C:\Program Files (x86)\Mozilla Thunderbird\")
    { Copy-Item -Force -Path ".\Data\Thunderbird\mozilla.cfg" -Destination "C:\Program Files (x86)\Mozilla Thunderbird\" }

    if (Test-Path -Path "C:\Program Files\Mozilla Thunderbird\")
    { Copy-Item -Force -Path ".\Data\Thunderbird\mozilla.cfg" -Destination "C:\Program Files\Mozilla Thunderbird\" }

    #Restart Thunderbird
    Stop-Process -Name "Thunderbird.exe" -Force
    if (Test-Path -Path "C:\Program Files\Mozilla Thunderbird\Thunderbird.exe")
    {
        Start-Process -FilePath "C:\Program Files\Mozilla Thunderbird\Thunderbird.exe"
    }
    else 
    {
        Start-Process -FilePath "C:\Program Files (x86)\Mozilla Thunderbird\Thunderbird.exe"
    }
}

try { Add-ExtraTools; } catch { Write-Error $_; }
try { Limit-AppLockerPerms; } catch { Write-Error $_; }