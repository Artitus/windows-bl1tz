#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

$appcmd = $(Join-Path $env:windir 'system32\inetsrv\appcmd.exe')

$protocol_value = '0x00000800'

function Set-IIS_Security
{
    

    #Global IIS security config
    if ($global:__UsesIIS__ -eq $true)
    {
        # Disable un-needed modules
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-HttpRedirect'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-ApplicationDevelopment'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-NetFxExtensibility'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-HealthAndDiagnostics'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-RequestMonitor'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-HttpTracing'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-URLAuthorization'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-Performance'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-HttpCompressionDynamic'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-ManagementScriptingTools'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-Metabase'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-StaticContent'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-WebDAV'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-ASPNET'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-HttpCompressionStatic'
        & Dism.exe '/online' '/disable-feature' '/featurename:IIS-LegacyScripts'

        # Enable features we want
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-HttpLogging'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-LoggingLibraries'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-Security'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-RequestFiltering'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-IPSecurity'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-WebServerManagementTools'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-DefaultDocument'
        & Dism.exe '/online' '/enable-feature' '/featurename:IIS-BasicAuthentication'
    
        # 1.3 (L1) Ensure 'directory browsing' is set to disabled (Scored)
        & $appcmd 'set' 'config' '/section:directoryBrowse' '/enabled:false'

        # 1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity (Scored)
        & $appcmd 'set' 'config' '-section:anonymousAuthentication' '/username:""' '--password'

        

        # 2.3 (L1) Ensure 'forms authentication' require SSL (Scored)
        & $appcmd 'set' 'config' '-section:system.web/authentication' '/mode:Forms'

        # 2.4 (L2) Ensure 'forms authentication' is set to use cookies (Scored)
        & $appcmd 'set' 'config' '-section:system.web/authentication' '/forms.cookieless:"UseCookies"'

        # 3.10 (L1) Ensure global .NET trust level is configured (Scored)
        & $appcmd 'set' 'config' '/commit:WEBROOT' '/section:trust' '/level:Medium'

        # 4.2 (L2) Ensure 'maxURL request filter' is configured (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' '/requestLimits.maxURL:2048'

        # 4.3 (L2) Ensure 'MaxQueryString request filter' is configured (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' '/requestLimits.maxQueryString:2048'

        # 4.4 (L2) Ensure non-ASCII characters in URLs are not allowed (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' '/allowHighBitCharacters:false'

        # 4.5 (L1) Ensure Double-Encoded requests will be rejected (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' '/allowDoubleEscaping:false'

        # 4.6 (L1) Ensure 'HTTP Trace Method' is disabled (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' "/+verbs.[verb=`'TRACE`', allowed=`'false`']"

        # 4.7 (L1) Ensure Unlisted File Extensions are not allowed (Scored)
        & $appcmd 'set' 'config' '/section:requestfiltering' '/fileExtensions.allowunlisted:false'

        # 4.8 (L1) Ensure Handler is not granted Write and Script/Execute (Scored)
        & $appcmd 'set' 'config' '/section:handlers' '/accessPolicy:Read, Script'

        # 4.9 (L1) Ensure 'notListedIsapisAllowed' is set to false (Scored)
        & $appcmd 'set' 'config' '-section:system.webServer/security/isapiCgiRestriction' '/notListedIsapisAllowed:false'

        # 4.10 (L1) Ensure 'notListedCgisAllowed' is set to false (Scored)
        & $appcmd 'set' 'config' '-section:system.webServer/security/isapiCgiRestriction' '/notListedCgisAllowed:false'

        # 5.1 (L1) Ensure Default IIS web log location is moved (Scored)
        & $appcmd 'set' 'config' '-section:sites' '-siteDefaults.logfile.directory:"C:\IIS_Logs\"'

        # IIS Fortify script
        Set-RestrictedInformation
        Set-HardenedCrypto

        # IIS hardening script
        Set-IISHardenedSettings

        #Set iis service startup to auto
        Set-Service -Name W3SVC -StartupType Automatic

        #Start iis service
        Restart-Service -Name W3SVC -Force

        # 1.7 (L1) Ensure WebDav feature is disabled (Scored)
        Uninstall-WindowsFeature -Name "Web-DAV-Publishing" -Remove
    }
    else
    {
        #Set iis service startup to disabled
        Set-Service -Name W3SVC -StartupType Disabled

        #Stop iis service
        Stop-Service -Name W3SVC -Force -NoWait
    }

    #IIS web server security (CIS)
    if ( $global:__IISWS__ -eq $true)
    {
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.) Complete these items from the IIS CIS Guide located at Resources\CIS_IIS.pdf"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.1) 2.5 (L1) Ensure 'cookie protection mode' is configured for forms authentication (Scored)"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.2) 2.6 (L1) Ensure transport layer security for 'basic authentication' is configured (Scored)"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.3) 2.7 (L1) Ensure 'passwordFormat' is not set to clear (Scored)"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.4) 2.8 (L2) Ensure 'credentials' are not stored in configuration files (Scored)"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.5) 5.2 (L1) Ensure Advanced IIS logging is enabled (Scored)"
        Add-Content -Path ".\Checklist\IIS.txt" -Force -Value "1.6) 5.3 (L1) Ensure 'ETW Logging' is enabled (Not Scored)"
        Start-Process -FilePath notepad.exe -ArgumentList ".\Checklist\IIS.txt"
    }
}

function Set-RestrictedInformation
{
    $appcmd = $(Join-Path $env:windir 'system32\inetsrv\appcmd.exe')

    Write-Output '[*] Removing IIS and ASP.NET server identification...'
    & $appcmd set config -section:system.webServer/rewrite/outboundRules "/+[name='Remove_RESPONSE_Server']" /commit:apphost
    & $appcmd set config -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].patternSyntax:`"Wildcard`"" /commit:apphost
    & $appcmd set config -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].match.serverVariable:RESPONSE_Server" "/[name='Remove_RESPONSE_Server'].match.pattern:`"*`"" /commit:apphost
    & $appcmd set config -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].action.type:`"Rewrite`"" "/[name='Remove_RESPONSE_Server'].action.value:`" `"" /commit:apphost

    & $appcmd set config /section:httpProtocol "/-customHeaders.[name='X-Powered-By']"

    # HSTS header
    Write-Output '[*] Configuring HSTS header...'
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='Strict-Transport-Security',value='max-age=31536000; includeSubDomains']"

    # Prevent framejacking.
    Write-Output '[*] Configuring other Security headers...'
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='cache-control',value='private, max-age=0, no-cache']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Content-Type-Options',value='nosniff']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-XSS-Protection',value='1; mode=block']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Download-Options',value='noopen']"
}

function Set-HardenedCrypto
{
    Write-Output '[*] Applying hardened SSL/TLS configuration...'
    
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name DefaultSecureProtocols -value $protocol_value -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name DefaultSecureProtocols -value $protocol_value -PropertyType 'DWord' -Force | Out-Null

    #7.4 (L1) Ensure TLS 1.0 is Disabled (Scored)
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null

    #7.5 (L1) Ensure TLS 1.1 is Disabled (Scored)
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
}

function Set-IISHardenedSettings
{
    # Disable Multi-Protocol Unified Hello
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Output 'Multi-Protocol Unified Hello has been disabled.'

    # Disable PCT 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Output 'PCT 1.0 has been disabled.'
	 
    # Disable SSL 2.0 (PCI Compliance)
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Output 'SSL 2.0 has been disabled.'

    # NOTE: If you disable SSL 3.0 the you may lock out some people still using
    # Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
    # for these people to fall back. Safer shopping certifications may require that
    # you disable SSLv3.
    #
    # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Output 'SSL 3.0 has been disabled.'

    # Re-create the ciphers key.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null

    # Disable insecure/weak ciphers.
    $insecureCiphers = @(
        'DES 56/56',
        'NULL',
        'RC2 128/128',
        'RC2 40/128',
        'RC2 56/128',
        'RC4 40/128',
        'RC4 56/128',
        'RC4 64/128',
        'RC4 128/128'
    )

    Foreach ($insecureCipher in $insecureCiphers)
    {
        $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
        $key.SetValue('Enabled', 0, 'DWord')
        $key.close()
        Write-Output "Weak cipher $insecureCipher has been disabled."
    }

    # Enable new secure ciphers.
    # - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
    # - 3DES: It is recommended to disable these in near future.
    $secureCiphers = @(
        'AES 128/128',
        'AES 256/256',
        'Triple DES 168/168'
    )

    Foreach ($secureCipher in $secureCiphers)
    {
        $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
        $key.close()
        Write-Output "Strong cipher $secureCipher has been enabled."
    }
	 
    # Set hashes configuration.
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
	 
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
    # Set KeyExchangeAlgorithms configuration.
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -name Enabled -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	 
    # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
    $cipherSuitesOrder = @(
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
        'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
        'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
        'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    )
    
    $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
    New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null

}

try { Set-IIS_Security; } catch { Write-Error $_; }