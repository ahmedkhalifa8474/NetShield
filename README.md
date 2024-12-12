# NetShield

# Network Shield - Automated IP and Domain Reputation Checker

This PowerShell script is designed to help identify suspicious IPs and domains in your network traffic. It checks for malicious activity using external services like **AbuseIPDB** and **VirusTotal** and blocks suspicious IPs using Windows Firewall.

## Features
- Monitor active network connections and identify suspicious IPs.

- Query **AbuseIPDB** for abuse confidence scores and **VirusTotal** for domain reputation.

- Automatically block suspicious IPs by creating firewall rules.

- Export suspicious IPs and domains to a CSV file for further analysis.

## Requirements

- **PowerShell 5.1** or higher (Windows)

- **API Keys** for **AbuseIPDB** and **VirusTotal**:

  - **AbuseIPDB API Key**: [Sign up for API Key](https://www.abuseipdb.com/)

  - **VirusTotal API Key**: [Sign up for API Key](https://www.virustotal.com/)

- Ensure that PowerShell has permission to execute scripts on your machine.

## Setup


1. **Clone or Download the repository**:




 ```bash
  git clone https://github.com/ahmedkhalifa8474/NetShield.git




Open PowerShell as Administrator.

Navigate to the directory where the script is located.

Run the script


