################################
## Script to remove malicious for detection ioc in misp
################################

# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
# Convert JSON input to a PowerShell array
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
# Suppress error messages
$ErrorActionPreference = "SilentlyContinue"

# Extract command and host IP information from the input array
$command = $INPUT_ARRAY."command"
$hostip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DHCPEnabled -ne $null -and $_.DefaultIPGateway -ne $null}).IPAddress | Select-Object -First 1

# Extract IOC (Indicator of Compromise) details from the input array
$IOCvalue = $INPUT_ARRAY."parameters"."alert"."data"."misp"."value"
$IOCtype = $INPUT_ARRAY."parameters"."alert"."data"."misp"."type"
$IOCdescription = $INPUT_ARRAY."parameters"."alert"."data"."misp"."source"."description"

# Check if the IOC is an IP address, domain, or hash based on IOCtype
if ($IOCtype -eq 'ip' -or $IOCtype -eq 'ip-src' -or $IOCtype -eq 'ip-dst') {
    foreach ($ip in $IOCvalue) {
        # Check if there is an existing firewall rule for the IP
        $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -ErrorAction SilentlyContinue
        if ($command -eq 'add' -AND $ip -ne '127.0.0.1' -AND $ip -ne '0.0.0.0' -AND $ip -ne $hostip -AND -not $existingRule) {
            # Add a new firewall rule to block the IP
            New-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ip
            echo "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip added to blocklist via Windows Firewall" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding ascii
        } elseif ($command -eq 'delete' -AND $ip -ne '127.0.0.1' -AND $ip -ne '0.0.0.0' -AND $ip -ne $hostip -AND $existingRule) {
            # Remove the existing firewall rule for the IP
            Remove-NetFirewallRule -DisplayName "Wazuh Active Response - $ip"
            echo "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip removed from blocklist via Windows Firewall" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding ascii
        }
    }
} elseif ($IOCtype -eq 'domain' -or $IOCtype -eq 'hostname') {
    # Handle domain types
    # Add domain to hosts file and resolve to 127.0.0.1
    $hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    $hostEntry = "127.0.0.1`t$IOCvalue"

    # Check if the domain is already in the hosts file
    if (-not (Select-String -Path $hostsPath -Pattern "^127\.0\.0\.1`t$IOCvalue$" -Quiet)) {
        Add-Content -Path $hostsPath -Value $hostEntry
        echo "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $IOCvalue added to hosts file with 127.0.0.1" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding ascii
    }
} elseif ($IOCtype -eq 'md5' -or $IOCtype -eq 'sha1' -or $IOCtype -eq 'sha256') {
    # Handle hash types (md5, sha1, sha256)
    # Extract path from IOCdescription if it contains hash type
    $pathPattern = "[C-Z]:.*?(?=\sFileCreate)"
    $pathMatches = [regex]::Matches($IOCdescription, $pathPattern) | Select-Object -First 1
    $pathmalicious = if ($pathMatches) { $pathMatches.Value } # else { "Path not found in description" }

    # Delete the file at the resolved path
    if (Test-Path $pathmalicious) {
        Remove-Item -Path $pathmalicious -Force
        echo "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - File $pathmalicious deleted" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding ascii
    } else {
        echo "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - File $pathmalicious not found" | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Append -Encoding ascii
    }
}
