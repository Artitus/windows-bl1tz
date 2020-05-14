#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Set-SecureFirewall
{
    & netsh.exe 'advfirewall' 'import' ".\Data\secure.wfw"
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    # Block telnet
    & netsh.exe 'advfirewall' 'firewall' 'set' 'rule' 'name="Telnet Server"' 'new' 'enable=no'

    # Block netcat
    & netsh.exe 'advfirewall' 'firewall' 'set' 'rule' 'name="netcat"' 'new' 'enable=no'

    # Block network discovery
    & netsh.exe 'advfirewall' 'firewall' 'set' 'rule' 'group="Network Discovery"' new 'enable=No'

    # Block remote registry inbound
    & netsh.exe 'advfirewall' 'firewall' 'add' 'rule' 'name="block_RemoteRegistry_in"' 'dir=in' 'service="RemoteRegistry"' 'action=block' 'enable=yes'

    # Block remote registry outbound
    & netsh.exe 'advfirewall' 'firewall' 'add' 'rule' 'name="block_RemoteRegistry_out"' 'dir=out' 'service="RemoteRegistry"' 'action=block' 'enable=yes'

    # Block SSH
    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block

    # Block telnet
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block

    # Block SMTP
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block

    # Block SNMP
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block 

    # Block POP3
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block

    Set-NetConnectionProfile -NetworkCategory Public
}

try { Set-SecureFirewall; } catch { Write-Error $_; }