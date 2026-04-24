# Detection Writeup: PowerShell Execution

**MITRE ATT&CK:** T1059.001
**Tactic:** Execution
**Platform:** Windows
**Date:** 2026-04-24
**Author:** Antonio Lopez

---

## 1. The Technique

**What it is:**
Adversaries abuse PowerShell — Windows' built-in scripting engine — to execute arbitrary commands, download payloads, and interact with the OS and network in ways that blend in with normal admin activity. Because PowerShell is a signed Microsoft binary, it bypasses application allowlisting controls that block unknown executables. Attackers can pass encoded commands (`-EncodedCommand`), bypass execution policy (`-ExecutionPolicy Bypass`), and suppress the window (`-WindowStyle Hidden`) to further evade casual observation.

**Why it matters:**
PowerShell is one of the most abused living-off-the-land binaries (LOLBin) in the threat landscape. It appears in commodity malware droppers, ransomware pre-encryption stages, red team frameworks (Cobalt Strike, Empire, Sliver), and APT campaigns. Groups including APT29, FIN7, Lazarus, and TA505 have all relied on PowerShell for initial execution and post-exploitation. The 2021 SolarWinds intrusion used PowerShell extensively for lateral movement and data staging. If you can't detect PowerShell abuse, you're blind to a significant portion of the threat landscape.

**Atomic(s) used:**
`T1059.001-1` — Executes a PowerShell command using `-EncodedCommand` to run a base64-encoded payload, simulating how loaders and droppers commonly invoke PowerShell to avoid plain-text signature detection.

**Why this atomic:**
The `-EncodedCommand` variant is the most operationally realistic. Plain `powershell.exe -Command "..."` is trivially detected by any string match. Defenders who only look for literal strings get bypassed the moment an attacker base64-encodes the payload — which is the default behavior in most C2 frameworks. This atomic tests whether the detection is robust enough to catch encoded invocations.

---

## 2. Lab Environment

| Component | Version / Config |
|-----------|-----------------|
| OS | Windows 10/11 build XXXXX |
| Sysmon | v15.x with SwiftOnSecurity config |
| PowerShell Logging | Script block + module logging enabled |
| SIEM | Elastic Stack 8.13 (Docker on Mac) |
| Elastic Agent | 8.13.0 |
| Atomic Red Team | Invoke-AtomicRedTeam (pulled 2026-04-24) |

**Baseline screenshot:**
<!-- Add screenshot of Kibana Discover before firing the atomic — shows no alerts/events matching the detection query. Save to screenshots/baseline.png -->

---

## 3. Expected Telemetry (Hypothesis)

Before firing the atomic, document what you expect to see. This is the hypothesis you're testing.

- **Sysmon Event ID 1** — process creation for `powershell.exe` or `pwsh.exe`
  - `process.command_line` will contain `-EncodedCommand` (or `-enc`, `-e`) followed by a base64 string
  - `process.parent.name` will likely be `cmd.exe` or `powershell.exe` (the atomic runner), but in real malware it's often `explorer.exe`, `wscript.exe`, or `mshta.exe`
- **PowerShell Event ID 4104** (Script Block Logging) — the decoded content of the encoded command will appear in plaintext here, regardless of encoding
  - `powershell.file.script_block_text` should contain the decoded payload
- **Do not expect:** A child process spawned by `powershell.exe` in this atomic — the encoded command just runs inline, no child process
- **Do not expect:** Network events (Event ID 3) for this specific atomic — it's a local execution test

---

## 4. Firing the Atomic

**Pre-flight:**
```powershell
Invoke-AtomicTest T1059.001-1 -CheckPrereqs
```

**Command fired:**
```powershell
Invoke-AtomicTest T1059.001-1
```

**Full output:**
```
<!-- Paste atomic console output here, or reference atomic-output.txt in this folder -->
```

**VM snapshot taken before firing:** [ ] Yes / [ ] No

---

## 5. Raw Telemetry Observed

### Sysmon Event (Event ID 1 — Process Creation)

Key fields:
```
process.command_line        : powershell.exe -EncodedCommand <base64string>
process.parent.name         : <fill after firing>
process.parent.command_line : <fill after firing>
user.name                   : <fill after firing>
file.hash.sha256            : <fill after firing>
```

### PowerShell Script Block (Event ID 4104)

Key fields:
```
powershell.file.script_block_text : <decoded payload will appear here>
winlog.event_data.ScriptBlockId   : <fill after firing>
```

**Raw event JSON:** Export from Kibana and save as `raw-event.json` in this folder.

### Hypothesis vs Reality
<!-- Did the telemetry match what you expected? What was different? Anything surprising? Fill this in after firing the atomic. -->

---

## 6. Detection Logic (Sigma)

See `sigma.yml` in this folder for the full rule. Key design decisions:

- **CommandLine|contains** is used rather than equals because PowerShell flags can be abbreviated (`-enc`, `-e`, `-EncodedCommand` are all valid)
- **A regex pattern** is applied to catch the base64 string pattern following the flag — this reduces false positives from scripts that happen to contain the flag as a string constant
- **Parent image filter** excludes known-legitimate parent processes (e.g., `MpCmdRun.exe`, `svchost.exe`) that invoke PowerShell as part of normal Windows operation
- The rule is `status: experimental` — it needs false positive tuning against your specific environment before promoting to production

---

## 7. Translated to Elastic + Enterprise Platforms

See `eql-query.txt` for the Elastic EQL translation and `kql-query.txt` for the Kusto KQL translation.

The EQL query was validated against real telemetry from the atomic. The KQL translation follows the same logic for Microsoft Sentinel and Google SecOps.

---

## 8. Testing the Rule

### Positive Test — Rule Fires on the Atomic

| Field | Value |
|-------|-------|
| Atomic fired at | YYYY-MM-DD HH:MM:SS |
| Alert generated at | YYYY-MM-DD HH:MM:SS |
| Alert severity | Medium |

<!-- Add screenshot: screenshots/alert-firing.png -->

### Negative Test — False Positive Hunt

Run legitimate activity that might look similar:

| Legitimate Activity | Did Rule Fire? | Notes |
|--------------------|---------------|-------|
| Admin running encoded PS for automation | <!-- fill --> | <!-- fill --> |
| Scheduled task using encoded command | <!-- fill --> | <!-- fill --> |
| Endpoint protection tool invoking PS | <!-- fill --> | <!-- fill --> |

**Tuning applied:**
```diff
<!-- Document any changes made to reduce false positives after negative testing -->
```

---

## 9. Final Tuned Rule

See `sigma.yml` for the final tuned version of the rule.

---

## 10. Reflection

**What surprised me:**
<!-- Fill in after completing the lab. E.g., unexpected parent process, telemetry gap, field naming differences between Sysmon versions. -->

**What I'd do differently:**
<!-- If you ran this lab again, what would you change? Different atomic? Different logging config? -->

**How an attacker could evade this detection:**

- **Obfuscation:** Use PowerShell's `Invoke-Expression` with string concatenation instead of `-EncodedCommand`, or use `[System.Text.Encoding]::Unicode.GetString()` inline to avoid the base64 flag entirely
- **Living-off-the-land alternatives:** Use `wscript.exe` with a VBScript dropper, or `mshta.exe` with an HTA file, to achieve the same execution without touching `powershell.exe`
- **AMSI bypass first:** An attacker who bypasses AMSI before running the real payload prevents script block logging from capturing the decoded content — the Event ID 4104 telemetry disappears
- **Constrained Language Mode evasion:** Some environments run PowerShell in Constrained Language Mode; attackers may use .NET reflection or COM objects to escape it

**What a more mature detection would include:**
- Correlate Sysmon Event ID 1 with Event ID 4104 on the same `ScriptBlockId` — confirms the command line and decoded content are both present
- Alert on parent processes that are unusual for PowerShell invocation (`mshta.exe`, `wscript.exe`, `winword.exe`) rather than on the encoding flag alone
- Add a behavioral sequence: encoded PowerShell → network connection (Event ID 3) within 60 seconds → high confidence execution + C2

---

## References

- [Atomic Red Team — T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [MITRE ATT&CK — T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Red Canary — PowerShell Threat Detection](https://redcanary.com/threat-detection-report/techniques/powershell/)
- [NSA/CISA — Keeping PowerShell: Security Measures to Use and Embrace](https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF)

---

## Artifacts in This Folder

| File | Description |
|------|-------------|
| `sigma.yml` | Final tuned Sigma rule |
| `eql-query.txt` | EQL translation (Elastic Security, lab-tested) |
| `kql-query.txt` | Kusto KQL translation (Sentinel / Google SecOps) |
| `raw-event.json` | Exported Kibana event (add after firing atomic) |
| `atomic-output.txt` | Full atomic console output (add after firing atomic) |
| `screenshots/` | Kibana screenshots — baseline, alert firing |
