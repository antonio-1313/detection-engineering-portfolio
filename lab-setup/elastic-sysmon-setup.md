# Lab Setup: Elastic Stack 8.13 + Sysmon + Atomic Red Team

This document covers the full detection engineering lab setup used in this portfolio. The architecture is:

- **Mac (host):** Elastic Stack 8.13 running in Docker — Elasticsearch, Kibana, Fleet Server
- **Windows VM (target):** Sysmon with SwiftOnSecurity config, Elastic Agent enrolled to Fleet, PowerShell logging enabled, Atomic Red Team installed

---

## 1. Elastic Stack 8.13 on Mac (Docker)

### Prerequisites

```bash
# Install Docker Desktop for Mac (if not installed)
# https://docs.docker.com/desktop/install/mac-install/

# Increase Docker memory to at least 4GB in Docker Desktop > Settings > Resources
# Elasticsearch is memory-hungry — 4GB minimum, 8GB recommended for a lab

# Verify Docker is running
docker info
```

### docker-compose.yml

Create a working directory and a `docker-compose.yml`:

```bash
mkdir ~/elastic-lab && cd ~/elastic-lab
```

```yaml
# docker-compose.yml — Elastic Stack 8.13
# Password is set via ELASTIC_PASSWORD — change this before use.

version: '3.8'
services:

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    environment:
      - discovery.type=single-node
      - ELASTIC_PASSWORD=changeme
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false   # HTTP only for local lab
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=changeme
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  fleet-server:
    image: docker.elastic.co/beats/elastic-agent:8.13.0
    environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_SERVER_ELASTICSEARCH_HOST=http://elasticsearch:9200
      - FLEET_SERVER_SERVICE_TOKEN=<paste token here>   # Generate in Kibana
      - FLEET_SERVER_INSECURE_HTTP=true
    ports:
      - "8220:8220"
    depends_on:
      - elasticsearch
      - kibana

volumes:
  esdata:
```

### Start the stack

```bash
cd ~/elastic-lab
docker compose up -d

# Watch logs until Kibana is ready (takes ~60-90 seconds)
docker compose logs -f kibana | grep "Kibana is now available"

# Verify Elasticsearch is up
curl -u elastic:changeme http://localhost:9200
```

### Generate the Fleet Server service token

```bash
# In Kibana: Fleet > Settings > Generate service token
# Paste the token into FLEET_SERVER_SERVICE_TOKEN in docker-compose.yml
# Then restart the fleet-server container:
docker compose restart fleet-server
```

---

## 2. Sysmon on Windows VM (SwiftOnSecurity Config)

Run all commands below in an **elevated PowerShell** on the Windows VM.

### Download Sysmon and config

```powershell
# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"

# Download SwiftOnSecurity Sysmon config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig-export.xml"
```

### Install Sysmon with the config

```powershell
# Install Sysmon (accept EULA)
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig-export.xml"

# Verify the service is running
Get-Service Sysmon64

# Check Sysmon version
& "$env:TEMP\Sysmon\Sysmon64.exe" -s
```

### Update Sysmon config (after future config changes)

```powershell
& "$env:TEMP\Sysmon\Sysmon64.exe" -c "$env:TEMP\sysmonconfig-export.xml"
```

### Verify Sysmon events are flowing

Open Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational.
You should see Event ID 1 (process creation) entries immediately.

---

## 3. PowerShell Script Block Logging

Script block logging decodes and logs the content of all PowerShell script blocks to Event ID 4104, regardless of obfuscation. This is the telemetry that catches encoded commands.

### Enable via Registry (no GPO needed for lab)

```powershell
# Create the ScriptBlockLogging registry path if it doesn't exist
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}

# Enable script block logging
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable module logging (logs pipeline execution details)
$modPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modPath)) {
    New-Item -Path $modPath -Force
}
Set-ItemProperty -Path $modPath -Name "EnableModuleLogging" -Value 1 -Type DWord

# Set module logging to cover all modules
$modNamesPath = "$modPath\ModuleNames"
if (-not (Test-Path $modNamesPath)) {
    New-Item -Path $modNamesPath -Force
}
Set-ItemProperty -Path $modNamesPath -Name "*" -Value "*"
```

### Verify logging is active

```powershell
# Confirm registry values are set
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

# Trigger a test log entry
powershell.exe -Command "Write-Output 'ScriptBlockLogging test'"

# Check Event Viewer: Applications and Services Logs > Microsoft > Windows > PowerShell > Operational
# Look for Event ID 4104 with your test string
```

---

## 4. Elastic Agent — Enroll Windows VM to Fleet

### Download Elastic Agent on Windows VM

```powershell
# Download Elastic Agent 8.13.0 (match your stack version exactly)
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-windows-x86_64.zip" -OutFile "$env:TEMP\elastic-agent.zip"
Expand-Archive -Path "$env:TEMP\elastic-agent.zip" -DestinationPath "$env:TEMP\elastic-agent"
cd "$env:TEMP\elastic-agent\elastic-agent-8.13.0-windows-x86_64"
```

### Get the enrollment token from Kibana

In Kibana: Fleet → Agent policies → Default policy → Enrollment tokens → Copy the token.

### Enroll the agent

```powershell
# Replace <YOUR_MAC_IP> with your Mac's IP (not localhost — the VM needs to reach it over the network)
# Replace <ENROLLMENT_TOKEN> with the token copied from Kibana

.\elastic-agent.exe install `
  --url=http://<YOUR_MAC_IP>:8220 `
  --enrollment-token=<ENROLLMENT_TOKEN> `
  --insecure
```

### Verify enrollment

```powershell
# Check agent service status on Windows
Get-Service "Elastic Agent"

# In Kibana: Fleet > Agents — your Windows VM should appear with status "Healthy"
```

### Add the Windows integration to the agent policy

In Kibana: Fleet → Agent policies → Default policy → Add integration → search "Windows" → add the **Windows** integration. This ships:
- Sysmon operational logs
- PowerShell operational logs (Event ID 4104)
- Windows Security Event logs

---

## 5. Atomic Red Team — Install on Windows VM

```powershell
# Set execution policy to allow the install (lab VM only — don't do this in production)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Install the Invoke-AtomicRedTeam module from PSGallery
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force

# Install the atomic test definitions
IEX (Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Verify install — list available atomics for T1059.001
Invoke-AtomicTest T1059.001 -ShowDetails
```

### Test workflow (example: T1059.001-1)

```powershell
# 1. Take a VM snapshot before every test run

# 2. Check prerequisites
Invoke-AtomicTest T1059.001-1 -CheckPrereqs

# 3. Install prerequisites if needed
Invoke-AtomicTest T1059.001-1 -GetPrereqs

# 4. Fire the atomic
Invoke-AtomicTest T1059.001-1

# 5. Check Kibana for telemetry (allow ~30-60 seconds for events to ship)

# 6. Clean up after the test
Invoke-AtomicTest T1059.001-1 -Cleanup
```

---

## Verifying the Full Pipeline

Use this checklist to confirm end-to-end telemetry flow before running atomics:

```
[ ] Docker stack is up: curl -u elastic:changeme http://localhost:9200 returns cluster info
[ ] Kibana accessible: http://localhost:5601
[ ] Fleet Server healthy: Kibana > Fleet > Fleet Server hosts shows "Healthy"
[ ] Windows Agent enrolled: Kibana > Fleet > Agents shows Windows VM as "Healthy"
[ ] Sysmon events flowing: Kibana Discover, filter by event.code: 1, see process creation events
[ ] Script block events flowing: Kibana Discover, filter by winlog.channel: "Microsoft-Windows-PowerShell/Operational" and event.code: 4104
[ ] Atomic Red Team installed: Invoke-AtomicTest T1059.001 -ShowDetails returns test details
```
