#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Set-SecureDNS
{
    if ($global:__UsesDNS__)
    {
        #Install the DNS tools
        Install-WindowsFeature -Name DNS -IncludeAllSubFeature -IncludeManagementTools

        #Import the powershell modules for DNS
        Import-Module DNSServer

        # Set DNS socket pool size to be bigger. Larger socket pools make it harder to guess which port to attack.
        Invoke-Expression "dnscmd /config /socketpoolsize 3000"

        # Set the cache server locking percent to 70%
        Set-DnsServerCache -LockingPercent 70

        # Clear the DNS cache on the server (in case its polluted)
        Clear-DnsServerCache -Force

        # Set server cache size to match microsoft's defaults
        Set-DnsServerCache -MaxKBSize 10240

        # Set caching parameters to match microsoft defaults
        Set-DnsServerCache -MaxTTL 02.00:00:00 -MaxNegativeTtl 00.00:20:00

        # Protect against cache pollution
        Set-DnsServerCache -PollutionProtection $true

        # Disable recursion to prevent attacks
        Invoke-Expression "dnscmd /config /NoRecursion 1"
        Set-DnsServerRecursion -Enable $false -RetryInterval 15 -SecureResponse $true

        # Set secure updates for DNS records
        Invoke-Expression "dnscmd /Config AllZones /AllowUpdate 2"

        # Force listen address to localhost instead of on all interfaces
        Invoke-Expression "dnscmd /ResetListenAddresses 127.0.0.1"

        # Set maximum number of error responses the server can send to a client per second
        Set-DnsServerResponseRateLimiting -ErrorsPerSec 4 -Force

        # The server will respond to 1 in every 10 dropped queries.
        Set-DnsServerResponseRateLimiting -LeakRate 10 -Force
        
        # Set maximum number of error responses the server can send to a client per second
        Set-DnsServerResponseRateLimiting -MaximumResponsesPerWindow 4 -Force

        # Set maximum number of error responses the server can send to a client per second
        Set-DnsServerResponseRateLimiting -Mode Enable -Force

        # Set maximum number of times the server will reply with a duplicate response per second
        Set-DnsServerResponseRateLimiting -ResponsesPerSec 4 -Force

        # The server will respond with a truncated message 1 in every 4 times it drops a request due to RRL
        Set-DnsServerResponseRateLimiting -TruncateRate 4 -Force

        # Set maximum number of times the server will reply with a duplicate response per second
        Set-DnsServerResponseRateLimiting -ResponsesPerSec 4 -Force

        # Prevent a memory leak issue on DNS servers
        Invoke-Expression "dnscmd /config AllZones /EnableDuplicateQuerySuppression 0"

        # Disable IVp6
        Invoke-Expression "dnscmd /config AllZones /EnableIPv6 0"

        # Allow online signing
        Invoke-Expression "dnscmd /config AllZones /EnableOnlineSigning 1"

        # Prevent forwarding updates to the primary zone (deters dns poisoning)
        Invoke-Expression "dnscmd /config AllZones /EnableUpdateForwarding 0"

        # Prevents NETBios resolutions from being cached in DNS (suppresses unnecessary info from attackers)
        Invoke-Expression "dnscmd /config AllZones /EnableWinsR 0"

        # Follow set policies on the server
        Invoke-Expression "dnscmd /config AllZones /IgnoreAllPolicies 0"

        # Set windows default
        Invoke-Expression "dnscmd /config AllZones /MaximumRodcRsoAttemptsPerCycle 100"

        # Forces stack to use a random udp port. Random = more secure because less likely to be guessed
        Invoke-Expression "dnscmd /config /SendPort 0"

        # Ignore CNAME conflicts
        Invoke-Expression "dnscmd /config AllZones /SilentlyIgnoreCNameUpdateConflicts 1"

        # Treat parsing errors as fatal
        Invoke-Expression "dnscmd /config /StrictFileParsing 1"

        # Logging
        Invoke-Expression "dnscmd /config /eventloglevel 4"

        # Disable zone transfers for all zones
        $zones = Get-DnsServerZone;

        # DNS enabler
        & netsh.exe advfirewall firewall set rule name="mDNS (UDP-In)" new enable=yes

        Foreach ($zone in $zones)
        {
            $zname = $zone.name;
            Invoke-Expression "dnscmd /ZoneResetSecondaries $zname /NoXfr"
        }
        Invoke-Expression "dnscmd /NoXfr"

        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "DefaultAgingState" -Value 1 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "DisableAutoReverseZones" -Value 1 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "EnableRegistryBoot" -Value 0 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "EventLogLevel" -Value 4 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "LogFileMaxSize" -Value 0x400000 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "LooseWildcarding" -Value 0 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "NoRecursion" -Value 1 -Force
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "SecureResponses" -Value 1 -Force
        
        New-Item -Path ".\Checklist\DNS.txt" -Force
        Add-Content -Path ".\Checklist\DNS.txt" -Force -Value "1) Open the dns manager from the server manager by right clicking the computer name in the dns tab."
        Add-Content -Path ".\Checklist\DNS.txt" -Force -Value "2) Rick click the domain (computer name) and click properties."
        Add-Content -Path ".\Checklist\DNS.txt" -Force -Value "3) Configure advanced (Disable recursion, enable pollution protection)"
        Add-Content -Path ".\Checklist\DNS.txt" -Force -Value "4) Close that, right click each Zone in the list (when you expand the domain) and enable DNSSec. Remember to use SHA3xx"
        Start-Process -FilePath notepad.exe -ArgumentList ".\Checklist\DNS.txt"
    }
}

try { Set-SecureDNS; } catch { Write-Error $_; }