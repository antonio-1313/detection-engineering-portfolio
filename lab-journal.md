# Lab Journal

## Environment Versions

| Component | Version |
|-----------|---------|
| Elastic Stack | 8.13 (Docker on Mac) |
| Kibana | 8.13 |
| Elastic Agent | 8.13.0 |
| Sysmon | v15.x with SwiftOnSecurity config |
| Atomic Red Team | Invoke-AtomicRedTeam (pulled 2026-04-24) |
| Windows VM | Windows 10/11 (target) |

---

## Entry Format

Each entry follows this structure:

```
### YYYY-MM-DD — [Short title of what you worked on]

**Goal:** What you set out to do.

**What happened:** Describe what actually occurred — including errors, unexpected behavior, and detours.

**Errors hit:**
- Error message or symptom
  - Root cause
  - Fix applied

**Outcome:** What state the lab is in after this session.

**Next:** What to tackle next session.
```

---

## Entries

### 2026-04-24 — Initial repo and lab setup

**Goal:** Stand up the detection engineering portfolio repo and document the lab environment.

**What happened:** Created the GitHub repo, scaffolded the folder structure, and wrote starter content for T1059.001 (PowerShell Execution). Lab environment was already partially configured — Elastic Stack 8.13 running in Docker on Mac, Windows VM with Sysmon and SwiftOnSecurity config, Elastic Agent enrolled to Fleet.

**Errors hit:**
- None during repo creation.
- Note: PowerShell script block logging must be confirmed enabled via `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` before firing atomics.

**Outcome:** Repo live at https://github.com/antonio-1313/detection-engineering-portfolio. T1059.001 detection stub ready — telemetry collection and rule tuning are the next steps.

**Next:** Fire `Invoke-AtomicTest T1059.001-1`, capture Sysmon Event ID 1 and PowerShell Event ID 4104, validate EQL query against real events in Kibana.
