﻿# Function to block IPs using Windows Firewall
Function Block-IP {
    param([string]$IP)
    
    Write-Host "Blocking IP: $IP" -ForegroundColor Red
    New-NetFirewallRule -DisplayName "Block $IP" -Direction Inbound -Protocol TCP -RemoteAddress $IP -Action Block -Enabled True
    New-NetFirewallRule -DisplayName "Block $IP" -Direction Outbound -Protocol TCP -RemoteAddress $IP -Action Block -Enabled True
}

# List of suspicious IPs with abuse confidence scores above 30
$suspiciousIPs = @(
    @{ IP = "204.79.197.203"; Score = 77 },
    @{ IP = "35.186.224.24"; Score = 44 }
)

# Iterate through the suspicious IPs and block them
foreach ($entry in $suspiciousIPs) {
    $IP = $entry.IP
    $score = $entry.Score
    
    If ($score -gt 30) {
        Write-Host "Suspicious IP found: $IP with abuse confidence score: $score" -ForegroundColor Red
        
        # Block the suspicious IP
        Block-IP -IP $IP
    }
}
