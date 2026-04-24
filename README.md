# Detection Engineering Portfolio

## About

This is an active detection engineering lab — not a course project. I build detections by emulating real adversary techniques using Atomic Red Team, capturing raw telemetry in Elastic Security, writing Sigma rules, and translating them to EQL and Kusto KQL for Elastic and Sentinel/Chronicle respectively. Every writeup includes the raw telemetry, the detection logic, false positive tuning, and an honest analysis of how an attacker could evade the rule. The goal is to document the full detection lifecycle the way it works in a real SOC or detection engineering role.

---

## Detection Status

| MITRE ID | Technique | Platform | Status |
|----------|-----------|----------|--------|
| [T1059.001](detections/T1059.001-powershell/) | PowerShell Execution | Windows | In Progress |

---

## Stack

| Layer | Tool |
|-------|------|
| SIEM | Elastic Stack 8.13 (Docker on Mac) |
| EDR Telemetry | Elastic Agent 8.13.0 + Fleet |
| Sysmon Config | SwiftOnSecurity `sysmonconfig-export.xml` |
| PowerShell Logging | Script block logging + module logging (GPO) |
| Adversary Emulation | Atomic Red Team via `Invoke-AtomicRedTeam` |
| Rule Format | Sigma (primary) |
| SIEM Translations | EQL (Elastic Security) · Kusto KQL (Sentinel / Google SecOps) |

---

## Repository Layout

```
detection-engineering-portfolio/
├── detections/              # One folder per MITRE technique
│   └── T1059.001-powershell/
│       ├── README.md        # Full 10-section detection writeup
│       ├── sigma.yml        # Tuned Sigma rule
│       ├── eql-query.txt    # EQL translation (Elastic, lab-tested)
│       ├── kql-query.txt    # Kusto KQL (Sentinel / Google SecOps)
│       └── screenshots/     # Kibana screenshots
├── templates/
│   └── detection-writeup-template.md
├── lab-setup/
│   └── elastic-sysmon-setup.md
├── aws-detection-pipeline/
│   └── README.md            # Serverless detection pipeline on AWS
└── lab-journal.md           # Running log of setup decisions and errors
```

---

## Links

- Portfolio: [antonio-lopez.netlify.app](https://antonio-lopez.netlify.app)
- GitHub: [github.com/antonio-1313](https://github.com/antonio-1313)
