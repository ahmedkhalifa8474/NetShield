Write-Host """
  _  __ _  __ _ _   _   __ _  __ _  ___   __ _  
 | |/ _` |/ _` | | | | / _` |/ _` |/ _ \ / _` | 
 | | (_| | (_| | |_| || (_| | (_| |  __/| (_| | 
 |_|\__,_|\__, |\__, (_)__,_|\__, |\___(_)__,_| 
          |___/ |___/       |___/               
                 Author: Kh4lifa0x
""" -ForegroundColor Cyan

# Set the API keys for AbuseIPDB and VirusTotal
$AbuseIPDBApiKey = "#############2a2facca1f64f021a45003a3ac0371288358b5"
$VirusTotalApiKey = "############46d88c6fdadb6f690c0bf819d556e0c"

# Ensure API keys are set
if (-not $AbuseIPDBApiKey -or -not $VirusTotalApiKey) {
    Write-Host "API keys are missing! Ensure the API keys are set in the script." -ForegroundColor Red
    exit
}

$StartTime = (Get-Date).AddHours(-6)
$EndTime = Get-Date

# Get network connections within the last 6 hours
Function Get-NetworkConnections {
    Get-NetTCPConnection | Where-Object {
        $_.State -eq 'Established' -and $_.CreationTime -ge $StartTime -and $_.CreationTime -le $EndTime
    } | Select-Object -Property RemoteAddress, RemotePort, @{Name='CreationTime'; Expression={(Get-Date $_.CreationTime).ToString('yyyy-MM-dd HH:mm:ss')}}
}

# Query AbuseIPDB for each IP address
Function Check-AbuseIPDB {
    param([string]$IP)
    $Url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP"
    $Headers = @{"Key"=$AbuseIPDBApiKey; "Accept"="application/json"}

    Try {
        $Response = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
        Return [PSCustomObject]@{
            IP = $IP
            AbuseConfidence = $Response.data.abuseConfidenceScore
            Categories = $Response.data.categories -join ","
        }
    } Catch {
        Write-Host "Failed to query AbuseIPDB for $IP" -ForegroundColor Red
        Return $null
    }
}

# Query VirusTotal for each domain
Function Check-VirusTotal {
    param([string]$Domain)
    $Url = "https://www.virustotal.com/api/v3/domains/$Domain"
    $Headers = @{"x-apikey"=$VirusTotalApiKey}

    Try {
        $Response = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
        $MaliciousCount = $Response.data.attributes.last_analysis_stats.malicious
        Return [PSCustomObject]@{
            Domain = $Domain
            Malicious = $MaliciousCount
        }
    } Catch {
        Write-Host "Failed to query VirusTotal for $Domain" -ForegroundColor Red
        Return $null
    }
}

# Get all the active network connections
$Connections = Get-NetworkConnections
Write-Host "Found $($Connections.Count) active network connections." -ForegroundColor Yellow

# Extract unique IPs from connections
$IPsToCheck = $Connections.RemoteAddress | Sort-Object -Unique

$Results = @()

foreach ($IP in $IPsToCheck) {
    Write-Host "Checking IP: $IP" -ForegroundColor Cyan

    # Check AbuseIPDB for IP reputation
    $IPResult = Check-AbuseIPDB -IP $IP
    If ($IPResult -and $IPResult.AbuseConfidence -gt 30) {
        Write-Host "Suspicious IP found: $IP with abuse confidence score: $($IPResult.AbuseConfidence)" -ForegroundColor Red
        $Results += $IPResult

        # Optionally, check VirusTotal for additional domain-related data (if the IP resolves to a domain)
        try {
            $Domain = [System.Net.Dns]::GetHostEntry($IP).HostName
            $DomainResult = Check-VirusTotal -Domain $Domain
            If ($DomainResult -and $DomainResult.Malicious -gt 0) {
                Write-Host "Malicious domain found: $Domain with $($DomainResult.Malicious) malicious reports" -ForegroundColor Red
                $Results += $DomainResult
            }
        } Catch {
            Write-Host "Failed to resolve domain for IP: $IP" -ForegroundColor Yellow
        }
    }
}

# If suspicious results were found, export to CSV
if ($Results.Count -gt 0) {
    $Results | Export-Csv -Path "Warning.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Suspicious activities exported to Warning.csv" -ForegroundColor Green
} else {
    Write-Host "No suspicious activities found." -ForegroundColor Yellow
}
