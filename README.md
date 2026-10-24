# Windows Endpoint Compromise Investigation: Registry Artifacts to SOC Incident Timeline

## Overview

This project simulates a phishing-to-persistence attack chain on an isolated Windows 10 VM, then investigates it purely through registry forensic artifacts — the same approach a SOC/DFIR analyst would use during real incident response. The goal was to determine what happened, which user was involved, whether persistence was configured, and what a SOC should do about it.

**Scope note:** The "malware" used in this lab is a renamed, harmless copy of `notepad.exe`. No real malicious code was used at any point. This project is a controlled simulation for learning and portfolio purposes.

---

## Scenario: "Invoice Phish to Persistence"

**Victim:** Standard Windows 10 user, single-user lab VM
**Attacker goal:** Gain a foothold on the endpoint and establish persistence

| Step | Attacker Action | Artifact Left Behind | MITRE ATT&CK |
|---|---|---|---|
| 1. Delivery | Phishing ZIP (`Invoice_Oct2026.zip`) placed in Downloads and extracted | RecentDocs, UserAssist | T1566.001 (Phishing: Spearphishing Attachment) |
| 2. Initial Execution | Extracted file renamed to `Invoice_Oct2026.pdf.exe` (double extension) and executed | UserAssist | T1204.002 (User Execution: Malicious File) |
| 3. Masquerading | File copied to `%LOCALAPPDATA%\Temp`, renamed to `svchost32.exe` (imitating a legitimate Windows process), executed again | UserAssist | T1036.005 (Masquerading: Match Legitimate Name or Location) |
| 4. Persistence | Run key `WindowsUpdateHelper` added under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, pointing to the Temp copy | NTUSER.DAT (Run key) | T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys) |
| 5. Data of Interest | Dummy files `Payroll_2026.xlsx` and `Vendor_Bank_Details.docx` opened on Desktop | RecentDocs | T1083 (File and Directory Discovery) |

---

## Lab Environment

- **VM:** Windows 10, VirtualBox, network adapter set to **Host-only** throughout the simulation (isolated from the internet by design, to preserve evidence integrity)
- **Payload:** Renamed copy of `notepad.exe` — used solely to generate realistic execution artifacts without any real malicious code
- **Methodology note:** Evidence was collected via **offline disk mounting** (shutting the VM down completely, then mounting its virtual disk read-only on the host with Arsenal Image Mounter) rather than live triage. This mirrors dead-box forensic acquisition and ensured no additional system activity contaminated the registry artifacts after the simulation.

---

## Ground-Truth Timeline (Attacker Actions)

```
[2026-10-23 07:50:29] - Invoice_Oct2026.pdf.exe executed from Downloads
[2026-10-23 07:53:58] - svchost32.exe executed from Temp
[2026-10-23 07:58:14] - Run key "WindowsUpdateHelper" created
[2026-10-23 08:03:56] - Payroll_2026.xlsx / Vendor_Bank_Details.docx opened


---

## Evidence Collection

Hives collected via offline mount of the VM's virtual disk:

| File | Source Path | Purpose |
|---|---|---|
| `SYSTEM` | `Windows\System32\config\SYSTEM` | ShimCache (AppCompatCache) |
| `NTUSER.DAT` | `Users\<user>\NTUSER.DAT` | Run keys, UserAssist, RecentDocs |
| `UsrClass.dat` | `Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags (folder navigation history) |
| `Amcache.hve` | `Windows\appcompat\Programs\Amcache.hve` | Execution evidence + file hashes |

**SAM** and **SOFTWARE** hives were reviewed but excluded from detailed analysis — the simulated scenario did not involve account creation or system-level configuration changes relevant to those hives.

All files were integrity-verified with SHA256 hash comparisons between the source (mounted disk) and the copied evidence file before analysis, after an initial copy of the SYSTEM hive was found to be corrupted and had to be re-acquired.

**Tools used:**
- [Registry Explorer](https://ericzimmerman.github.io/) — NTUSER.DAT, UsrClass.dat
- [AmcacheParser](https://ericzimmerman.github.io/) — Amcache.hve
- [AppCompatCacheParser](https://ericzimmerman.github.io/) — SYSTEM hive (ShimCache)
- Arsenal Image Mounter — offline disk mounting

---

## Findings

### 1. Delivery and Execution (UserAssist, RecentDocs)

UserAssist (NTUSER.DAT) recorded both GUI-launched executions:
- `Invoice_Oct2026.pdf.exe` — run count 1, timestamp matching the ground-truth log
- `svchost32.exe` — run count 1, timestamp matching the ground-truth log

RecentDocs confirmed the ZIP file and extracted executable were accessed via Explorer, consistent with a user opening a downloaded attachment.

### 2. Masquerading (File Location + Naming)

The payload was copied from Downloads to `%LOCALAPPDATA%\Temp` and renamed to `svchost32.exe` — a name intended to imitate the legitimate Windows process `svchost.exe`, but located in a non-standard, user-writable path. Legitimate `svchost.exe` only runs from `C:\Windows\System32\`, making this location/name mismatch a strong indicator of malicious intent on its own, independent of any hash or signature check.


### 3. Persistence (Run Key)

A Run key named `WindowsUpdateHelper` was created under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, pointing to the Temp-located payload. This ensures the payload would execute automatically at every user logon.

Notably, the value name (`WindowsUpdateHelper`) is designed to blend in with legitimate Windows Update-related entries — a common social-engineering trick aimed at anyone manually reviewing the Run key.


### 4. Amcache and ShimCache Gap — A Key Finding

Neither **Amcache** nor **ShimCache** captured the two execution events (`Invoice_Oct2026.pdf.exe`, `svchost32.exe`), despite a full VM restart performed specifically to flush both caches to disk.

This is a genuine, documented limitation rather than an investigation error:

- **Amcache** population relies partly on the **Microsoft Compatibility Appraiser** scheduled task, which runs periodically rather than instantly on every execution. A single short VM session may not trigger this task before shutdown.
- **ShimCache** is only fully committed to the registry at shutdown/restart, and Windows 10/11 can be inconsistent about adding newly-seen entries within a single short-lived session, particularly in virtualized environments.

**SOC takeaway:** Analysts should not treat the absence of an entry in Amcache or ShimCache as proof that a file never executed. These artifacts are valuable corroborating evidence when present, but should never be the sole basis for ruling out execution. UserAssist, Prefetch, and Windows Event Logs (4688) are more immediate and session-independent sources of execution evidence and should be checked in parallel.

### 5. Data of Interest (RecentDocs)

RecentDocs showed access to two dummy files on the Desktop (`Payroll_2026.xlsx`, `Vendor_Bank_Details.docx`), representing the kind of sensitive-data access a real attacker might pursue after establishing persistence.




---

## MITRE ATT&CK Mapping

| Technique ID | Name | Where Observed |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | ZIP delivery to Downloads |
| T1204.002 | User Execution: Malicious File | Double-click execution of renamed payload |
| T1036.005 | Masquerading: Match Legitimate Name or Location | `svchost32.exe` in Temp |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | `WindowsUpdateHelper` Run key |
| T1083 | File and Directory Discovery | Access to Payroll/Vendor files |

---

## SOC Detection and Response

### Detection logic used in this investigation

- File named to imitate a system process (`svchost32.exe`) but running from a non-system path (`%LOCALAPPDATA%\Temp`) → masquerading indicator
- Double file extension (`.pdf.exe`) → classic phishing/social-engineering indicator
- Run key value pointing to a Temp/AppData path rather than Program Files → persistence red flag
- Tight timeline (all actions within a short window) → consistent with a scripted attack chain rather than normal user behavior

### Containment

- Isolate the affected host from the network
- Disable the affected user account pending investigation

### Eradication

- Remove the `WindowsUpdateHelper` Run key
- Delete the payload from both Downloads and Temp

### Recovery

- Reset the affected user's credentials
- Rebuild/reimage the host if the payload were a real malicious binary (in a real incident, a "cleaned" host should not be trusted for sensitive use)

### Hunting (organization-wide)

- Search EDR/SIEM for the payload's SHA1/SHA256 hash across all endpoints
- Search for the Run key value name (`WindowsUpdateHelper`) or similar naming patterns org-wide
- Check email gateway logs for other recipients of the same phishing attachment
- Correlate with Windows Event Logs (4688 — process creation) for independent confirmation of execution

### Preventive Recommendations

- Block or flag double-extension executables at the email gateway
- Alert on Run key writes pointing to Temp/AppData paths (via Sysmon Event ID 13 + SIEM rule)
- Deploy Sysmon with a tuned configuration (e.g., SwiftOnSecurity's sysmon-config) for richer, more reliable process and registry telemetry than native Windows auditing alone

---


---

## Limitations

- This is a controlled lab simulation using a harmless renamed executable, not real malware.
- SAM and SOFTWARE hives were not analyzed in depth, as the scenario did not involve account creation or OS-level configuration changes.
- Amcache and ShimCache did not capture the simulated execution events (see Finding #4) — UserAssist served as the primary execution evidence in this investigation.
- Native Windows auditing (Process Creation, Registry auditing) was not enabled prior to the attack simulation, limiting initial Event Log correlation; this was addressed in a follow-up phase using Sysmon.
There is no use of SIEM tools like SPLUNK in this investigation.

---

## Author's Note

This project was built and investigated end-to-end in a single day as a self-driven learning exercise, combining registry forensics with SOC-oriented detection and response thinking. Feedback from anyone working in DFIR or SOC roles is welcome.
