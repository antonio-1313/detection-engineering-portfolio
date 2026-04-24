# Detection Writeup: [Technique Name]

**MITRE ATT&CK:** TXXXX.XXX  
**Tactic:** [e.g., Execution, Defense Evasion, Credential Access]  
**Platform:** [Windows / Linux / macOS / Cloud]  
**Date:** YYYY-MM-DD  
**Author:** [Your Name]

---

## 1. The Technique

**What it is:**  
<!-- Brief 2-3 sentence description of the technique. Avoid copy-pasting MITRE verbatim — put it in your own words. -->

**Why it matters:**  
<!-- Why defenders should care. Which threat actors use it? Real-world incidents? -->

**Atomic(s) used:**  
`TXXXX.XXX-N` — [short description of what this atomic does]

**Why this atomic:**  
<!-- Why did you pick this specific atomic over other variations? -->

---

## 2. Lab Environment

| Component        | Version / Config                                      |
|------------------|-------------------------------------------------------|
| OS               | Windows 10/11 build XXXXX                             |
| Sysmon           | vXX.XX with SwiftOnSecurity config                    |
| PowerShell Logging | Script block + module logging enabled               |
| SIEM             | Elastic Stack 8.13 (Docker on Mac)                    |
| Elastic Agent    | 8.13.0                                                |
| Atomic Red Team  | commit SHA or date pulled                             |

**Baseline screenshot:**  
<!-- Screenshot of Kibana Discover before any atomic runs -->

---

## 3. Expected Telemetry (Hypothesis)

Before firing the atomic, write down what you expect to see. This makes you a better detection engineer — you're testing a hypothesis, not fishing.

- Expect Sysmon Event ID 1 (process creation) with `process.name: ...`
- Expect PowerShell Event ID 4104 with script block containing `...`
- Expect parent process: `...`
- Do **not** expect: `...`

---

## 4. Firing the Atomic

**Pre-flight:**
```powershell
Invoke-AtomicTest TXXXX.XXX-N -CheckPrereqs
```

**Command fired:**
```powershell
Invoke-AtomicTest TXXXX.XXX-N
```

**Full output:**
```
<!-- Paste the atomic's console output, or link to atomic-output.txt in the same folder. -->
```

**VM snapshot taken before firing:** ✅ / ❌

---

## 5. Raw Telemetry Observed

### Sysmon Event (Event ID 1 — Process Creation)

Key fields:
```
process.command_line      : ...
process.parent.name       : ...
process.parent.command_line : ...
user.name                 : ...
file.hash.sha256          : ...
```

### PowerShell Script Block (Event ID 4104)

Key fields:
```
powershell.file.script_block_text : ...
winlog.event_data.ScriptBlockId   : ...
```

**Raw event JSON:** See `raw-event.json` for the full event export from Kibana.

### Hypothesis vs Reality
<!-- Did the telemetry match what you expected? What was different? Anything surprising? -->

---

## 6. Detection Logic (Sigma)

```yaml
title: [Descriptive title of what this detects]
id: <generate a UUID — e.g., via `uuidgen` or https://www.uuidgenerator.net/>
status: experimental
description: |
  [Clear description of what malicious behavior this rule catches.]
references:
  - https://attack.mitre.org/techniques/TXXXX/XXX/
  - [link to threat report / blog that inspired it]
author: [Your Name]
date: YYYY-MM-DD
tags:
  - attack.txxxx.xxx
  - attack.<tactic>
logsource:
  product: windows
  service: sysmon  # or powershell, security, etc.
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - '...'
      - '...'
  filter:
    ParentImage|endswith:
      - '\legitimate.exe'
  condition: selection and not filter
falsepositives:
  - [Known legitimate use cases]
level: medium  # low / medium / high / critical
```

**Why this logic:**  
<!-- Explain each detection field. Why CommandLine|contains and not equals? Why this ParentImage filter? -->

---

## 7. Translated to Elastic + Enterprise Platforms

### EQL — Elastic Security (Lab-Tested)
*Primary. This is the query you actually ran and validated in your lab.*

```eql
process where event.type == "start" and
  process.command_line : "*pattern*" and
  not process.parent.name : "legitimate.exe"
```

### KQL — Kusto Query Language (Sentinel / Google SecOps)
*Enterprise translation. Write this every time — even without a Sentinel or Chronicle environment to test in, the translation shows cross-platform fluency. Kusto KQL is used in Microsoft Sentinel, Azure Log Analytics, and Google SecOps/Chronicle (which adopted a Kusto-like dialect).*

```kql
SecurityEvent
| where EventID == 1
| where CommandLine contains "pattern"
| where ParentProcessName !endswith "legitimate.exe"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
```

> **Note — two things called KQL:** Elastic's Kibana also has a "KQL" (Kibana Query Language) used in Discover and dashboards. It's a different, simpler syntax. When your portfolio says KQL, mean Kusto unless you specify otherwise — that's the one enterprise employers care about.

### Google SecOps / Chronicle — Optional
*Include only if you have Chronicle access or want to show BigQuery SQL fluency specifically.*

```sql
SELECT
  hostname,
  process_name,
  command_line,
  parent_process_name,
  timestamp
FROM
  `your_dataset.process_events`
WHERE
  command_line LIKE '%pattern%'
  AND parent_process_name != 'legitimate.exe'
  AND DATE(timestamp) = CURRENT_DATE()
```

---

## 8. Testing the Rule

### Positive Test — Rule Fires on the Atomic

| Field | Value |
|-------|-------|
| Atomic fired at | YYYY-MM-DD HH:MM:SS |
| Alert generated at | YYYY-MM-DD HH:MM:SS |
| Alert severity | ... |

<!-- Screenshot of the alert firing in Kibana Security -->

### Negative Test — False Positive Hunt

Run legitimate activity that might look similar and see what triggers:

| Legitimate Activity | Did Rule Fire? | Notes |
|---------------------|---------------|-------|
| Admin PowerShell usage | Yes / No | … |
| Scheduled task running PS | Yes / No | … |
| Dev running a script | Yes / No | … |

**Tuning applied:**
```diff
- CommandLine|contains: '-enc'
+ CommandLine|contains: '-enc '
+ CommandLine|re: '(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{20,}'
```
<!-- What did you change to reduce false positives? Why? Show the diff. -->

---

## 9. Final Tuned Rule

```yaml
# Paste the cleaned-up, tuned version of the Sigma rule here
```

---

## 10. Reflection

**What surprised me:**  
<!-- Something you didn't expect. E.g., "I assumed the parent would be explorer.exe but it was..." -->

**What I'd do differently:**  
<!-- If you did this lab again, what would you change? -->

**How an attacker could evade this detection:**

- **Obfuscation:** …
- **Living-off-the-land alternatives:** …
- **Timing / volume evasion:** …

**What a more mature detection would include:**  
<!-- To catch the evasions above, what additional telemetry or correlation would you need? -->

---

## References / Further Reading

- [Red Canary Atomic Red Team — TXXXX.XXX](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/TXXXX.XXX/TXXXX.XXX.md)
- [MITRE ATT&CK — TXXXX.XXX](https://attack.mitre.org/techniques/TXXXX/XXX/)
- [Any threat reports referenced]

---

## Artifacts in This Folder

| File | Description |
|------|-------------|
| `sigma.yml` | Final tuned Sigma rule |
| `eql-query.txt` | EQL translation (Elastic Security, lab-tested) |
| `kql-query.txt` | Kusto KQL translation (Sentinel / Google SecOps) |
| `raw-event.json` | Exported Kibana event |
| `atomic-output.txt` | Full atomic console output |
| `screenshots/` | All screenshots referenced above |
