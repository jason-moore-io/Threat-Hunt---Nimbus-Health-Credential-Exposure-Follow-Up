# 🛡️ Threat Hunt Report – Nimbus Health: Credential Exposure Follow-Up

---

## 📌 Executive Summary

A newly hired Nimbus Health IT Support Technician, Mason Reed (`m.reed`), published enough personal information online — job title, employer, tenure, and a personal contact email — to let an attacker connect his identity to Nimbus Health and pull his email through breach-exposure data, surfacing a reused password from recent credential-leak sources. That same attacker found an internally classified support document sitting exposed in a public document cache, which named the exact IT workstation (NH-WKS-IT-01) configured to accept remote domain-credential logons — handing over both a valid credential and its target in one motion. The attacker successfully authenticated over RDP, enumerated the host and domain using only native Windows tools, accessed HR data outside the account's authorized role, staged and archived that data locally, and exfiltrated it via RDP client-drive redirection — all without deploying any malware. This was an external account takeover via credential reuse, not insider misconduct, and the exposure of employee personal data creates a formal breach-notification obligation that goes beyond an internal IT fix.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Nimbus Health outpatient clinic environment, domain `corp.nimbushealth.com`, managed by Log(N) Pacific as MSP. Investigation scoped to a single host, **NH-WKS-IT-01** (IT Administration workstation, public IP 135.237.163.62), during a period of rapid staffing expansion where new hires shared existing department workstations.
- **Data Sources:** Microsoft Sentinel (law-cyber-range workspace), MDE tables — `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`. Supplemented by open-source artefacts collected pre-query: public professional profile, breach-exposure report, and a cached internal IT reference document.
- **Timeframe:** **2026-05-25 → 2026-05-30**

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1 – Account Identification](#-flag-1)
  - [🚩 Flag 2 – Public Role](#-flag-2)
  - [🚩 Flag 3 – Personal Contact Address](#-flag-3)
  - [🚩 Flag 4 – Remote Support Endpoint](#-flag-4)
  - [🚩 Flag 5 – Breach Explaining Reuse](#-flag-5)
  - [🚩 Flag 6 – The Guessing Source](#-flag-6)
  - [🚩 Flag 7 – Logon Type](#-flag-7)
  - [🚩 Flag 8 – The Second Source](#-flag-8)
  - [🚩 Flag 9 – The Command Burst](#-flag-9)
  - [🚩 Flag 10 – Signal or Noise](#-flag-10)
  - [🚩 Flag 11 – Remote Share Enumeration](#-flag-11)
  - [🚩 Flag 12 – HR Group Enumeration](#-flag-12)
  - [🚩 Flag 13 – Out-of-Role File Access](#-flag-13)
  - [🚩 Flag 14 – Staging Folder](#-flag-14)
  - [🚩 Flag 15 – The Archive](#-flag-15)
  - [🚩 Flag 16 – Exfiltration Destination](#-flag-16)
  - [🚩 Flag 17 – Persistence Check](#-flag-17)
  - [🚩 Flag 18 – File Server Access Method](#-flag-18)
  - [🚩 Flag 19 – The Honest Read](#-flag-19)
  - [🚩 Flag 20 – Proving Credential Reuse](#-flag-20)
  - [🚩 Flag 21 – The Second Session](#-flag-21)
  - [🚩 Flag 22 – Pre-Exfiltration Recon](#-flag-22)
  - [🚩 Flag 23 – First Containment Action](#-flag-23)
  - [🚩 Flag 24 – Data Obligation](#-flag-24)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This hunt began outside the SIEM, working four recovered OSINT artefacts before a single query was run: a public LinkedIn profile, a breach-exposure report, a cached internal IT reference document, and Nimbus's role matrix. Together, these established *why* Mason Reed (a new IT hire) was targeted, *how* his password was likely still valid, and *which* specific host an attacker would aim it at.

Telemetry then confirmed the theory. The host, NH-WKS-IT-01, sits under constant credential-stuffing background noise from dozens of unrelated sources — none of which succeeded. One low-volume source (3 failed attempts, then success) stood apart, consistent with an attacker holding a small set of known-good credential candidates from breach data rather than blind spraying. The successful logon was RemoteInteractive (RDP), not a local console session.

Once on the box, the operator ran a short, human-paced burst of native reconnaissance commands (`whoami`, `hostname`, `ipconfig /all`, `whoami /groups`) after the Windows/Edge first-run housekeeping noise settled. A file deletion inside that same window was misleading at first glance but confirmed to be OneDrive's own installer cleanup, not operator activity. The operator reconnected roughly ten minutes later from a second external IP, continued enumeration beyond the local host (`net view \\NH-FS-01`), and enumerated HR's domain group (`net group "NH-HR-Users" /domain`) — access with no legitimate basis under the account's IT-only role. HR data was then opened directly over SMB (no logon to the file server itself), staged locally into a dedicated folder, compressed into a single archive, and walked out through the existing RDP session via client-drive redirection — no upload, no cloud service, no distinct network exfil channel to catch by conventional means. No persistence mechanism, malware, or exploitation was found anywhere in the evidence.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Reconnaissance – Gather Victim Identity Info | T1589 | Medium |
| 2 | Reconnaissance – Search Open Websites/Domains | T1593 | Medium |
| 3 | Reconnaissance – Gather Victim Identity Info (Credentials/Contact) | T1589.001 | High |
| 4 | Reconnaissance – Gather Victim Host Info | T1592 | High |
| 5 | Resource Development – Compromise Accounts (Credential Reuse) | T1586 / T1589.001 | High |
| 6 | Credential Access – Brute Force (Password Guessing, low-volume) | T1110.001 | High |
| 7 | Initial Access – Valid Accounts (Remote Services) | T1078 / T1021.001 | Critical |
| 8 | Initial Access – Valid Accounts (Multiple Source IPs) | T1078 | High |
| 9 | Discovery – System Information Discovery | T1082 | Medium |
| 10 | Defense Evasion (ruled out) – File Deletion, non-malicious | N/A (native OS behavior) | Informational |
| 11 | Discovery – Network Share Discovery | T1135 | High |
| 12 | Discovery – Account/Group Discovery (Domain) | T1069.002 | High |
| 13 | Collection – Data from Network Shared Drive | T1039 | Critical |
| 14 | Collection – Local Data Staging | T1074.001 | Critical |
| 15 | Collection – Archive Collected Data | T1560 | Critical |
| 16 | Exfiltration – Exfiltration Over RDP Channel | T1021.001 / T1048 | Critical |
| 17 | Persistence (ruled out) – None established | N/A | Informational |
| 18 | Lateral Movement (ruled out) – Remote access via SMB path, not file server logon | T1021 (ruled out for file server) | Informational |
| 19 | Overall Technique Class – Valid Accounts / LOLBins | T1078, T1218 (native tools) | Critical |
| 20 | Credential Access – Credential Stuffing/Reuse (confirmed) | T1110.004 | High |

---

## 🔍 Flag Analysis

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Account Identification</strong></summary>

### 🎯 Objective
Identify the Nimbus account under review.

### 📌 Finding
Cross-referencing the role matrix (Artifact 04) for recently joined accounts against the public LinkedIn profile (Artifact 01) identified the subject.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | m.reed |
| Full Name | Mason Reed |
| Role | IT Support Technician |
| Start Date | 2026-04-28 |
| Source | Artifact 01 (LinkedIn), Artifact 04 (Role Matrix) |

### 💡 Why it matters
Establishes the identity at the center of the entire hunt — every subsequent query is scoped to this account.

### 🔧 KQL Query Used
None — identified via OSINT artefact correlation, not telemetry.

### 🖼️ Screenshot
<img width="1448" height="1006" alt="Flag_01_Mason_Reed_Linkedin_Profile" src="https://github.com/user-attachments/assets/30f76029-93fd-4c2e-9ae1-040a2fb21449"/> <img width="705" height="201" alt="Flag01B_Nimbus_Health__Security_Operations" src="https://github.com/user-attachments/assets/f3c884d2-b871-4523-baed-ae069b0b0970" />


</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Public Role</strong></summary>

### 🎯 Objective
Determine what an attacker could learn about the target's job function from public sources.

### 📌 Finding
Job title as published verbatim on LinkedIn.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source | Artifact 01 (LinkedIn) |
| Job Title | IT Support Technician at Nimbus Health |

### 💡 Why it matters
Confirms the account's employer, role, and — combined with his "About" text — broad cross-department access scope, all self-published.

### 🔧 KQL Query Used
None — OSINT.

### 🖼️ Screenshot
<<img width="1448" height="1006" alt="Flag02_Mason_Reed_Linkedin_Profile" src="https://github.com/user-attachments/assets/bf7c4fcd-54a1-4a0e-b077-6a27a41ea3d0" />


</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Personal Contact Address</strong></summary>

### 🎯 Objective
Identify the pivot point from public identity to an attacker-actionable search input.

### 📌 Finding
Personal email address listed publicly on the LinkedIn profile.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source | Artifact 01 (LinkedIn Contact Info) |
| Email | mason.reed@hotmail.com |

### 💡 Why it matters
This is the exact input an attacker would run through a breach-exposure lookup service.

### 🔧 KQL Query Used
None — OSINT.

### 🖼️ Screenshot
<<img width="1448" height="1006" alt="Flag03_Mason_Reed_Linkedin_Profile" src="https://github.com/user-attachments/assets/68aeb325-c828-4197-ab5e-41cabce7162c" />


</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Remote Support Endpoint</strong></summary>

### 🎯 Objective
Identify the specific machine and address an attacker would target.

### 📌 Finding
A cached internal IT reference document exposed the designated remote-support endpoint and its public IP.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source | Artifact 03 (Cached Support Reference), corroborated by Artifact 04 |
| System | NH-WKS-IT-01 |
| Public IP | 135.237.163.62 |
| Internal IP | 10.1.0.233 |

### 💡 Why it matters
Confirms the exact host and address the attacker used, and that the document explicitly instructed use of domain credentials — a direct match to the attack that followed.

### 🔧 KQL Query Used
None — OSINT, cross-confirmed against Artefact 04's environment table.

### 🖼️ Screenshot
<img width="340" height="280" alt="Flag04_Copy_of_Nimbus_Health__Security_Operations_Artifacts_May_-_Sheet1" src="https://github.com/user-attachments/assets/c872a340-aa34-438b-bab9-cb07662b77eb" />

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Breach Explaining Reuse</strong></summary>

### 🎯 Objective
Determine which of three breach hits actually explains a working password against a corporate account today.

### 📌 Finding
Three breaches returned for the personal email; only the most recent, purpose-built credential-stuffing dataset plausibly explains a still-valid password.

### 🔍 Evidence

| Breach | Date | Usable? | Reasoning |
|---|---|---|---|
| MySpace | ~2008 (disclosed 2016) | No | 18 years old; weak/partial SHA1 hash format, unlikely to reflect current password |
| Telegram Combolists | May 2024 | Partially | Plaintext-adjacent, included site-of-use context |
| Synthient Credential Stuffing Threat Data | April 2025 | **Yes** | Most recent (~13 months pre-incident); explicitly built and used to compromise accounts of victims who reused passwords |

### 💡 Why it matters
Establishes the credible mechanism by which a still-working password reached the attacker.

### 🔧 KQL Query Used
None — OSINT (Artifact 02).

### 🖼️ Screenshot
<img width="792" height="612" alt="Flag05a_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/cc4b160a-279c-4807-bc72-b322d5bea22e" />
<img width="627" height="560" alt="Flag05b_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/c2a81429-42c7-4699-88a0-f6608fd2cee6" />
<img width="260" height="520" alt="Flag05c_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/ca04c765-7878-412f-be91-60f2ad19819c" />
<img width="349" height="769" alt="Flag05d_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/24f115db-5e65-4370-a3fe-939a1e661fc2" />
<img width="390" height="592" alt="Flag05e_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/0ba51aa2-fa1d-439f-8d4f-0a2f831ef256" />
<img width="347" height="553" alt="Flag05f_mason_reed_haveibeenpwned" src="https://github.com/user-attachments/assets/6810b835-85e9-469d-a0e8-763f93889468" />
</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: The Guessing Source</strong></summary>

### 🎯 Objective
Separate the targeted, successful attempt from constant brute-force background noise.

### 📌 Finding
One source IP shows a low-volume, targeted pattern (3 failures, then success) distinct from dozens of noisy, unsuccessful sources.

### 🔍 Evidence

| RemoteIP | FailCount | SuccessCount |
|---|---|---|
| **116.45.242.115** | 3 | 3 |
| 45.131.194.61 | 0 | 4 |
| 216.73.163.30 | 2 | 0 |
| 45.131.194.209 | 2 | 0 |
| ::1 (loopback) | 0 | 1 |

### 💡 Why it matters
Identifies the actual intrusion source amid heavy background scanning noise.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| summarize FailCount = countif(ActionType == "LogonFailed"),
            SuccessCount = countif(ActionType == "LogonSuccess"),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by RemoteIP
| order by SuccessCount desc, FailCount asc
```

### 🖼️ Screenshot
<img width="974" height="799" alt="Flag06_The Guessing Source" src="https://github.com/user-attachments/assets/df8d7deb-c453-4fec-8f38-4d861feb5454">
</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Logon Type</strong></summary>

### 🎯 Objective
Determine whether the successful logon was local or remote.

### 📌 Finding
LogonType 10 — RemoteInteractive (RDP), not a local console session.

### 🔍 Evidence

| Field | Value |
|------|-------|
| LogonType (numeric) | 10 |
| LogonType (descriptive) | RemoteInteractive |

### 💡 Why it matters
Confirms remote access consistent with the exposed remote-support endpoint's stated purpose.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where ActionType == "LogonSuccess"
| where RemoteIP == "116.45.242.115"
| project Timestamp, ActionType, LogonType, RemoteIP, RemoteIPType, IsLocalAdmin
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1148" height="655" alt="Flag07_Login Type" src="https://github.com/user-attachments/assets/c1b482ad-8134-4194-90e7-26ddc405657b" />

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: The Second Source</strong></summary>

### 🎯 Objective
Determine whether the attacker used more than one external address.

### 📌 Finding
A second successful RemoteInteractive logon occurred from a different external IP shortly after the first session.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Second RemoteIP | 45.131.194.61 |
| Timestamp | 2026-05-29T01:40:59Z |

### 💡 Why it matters
Shows the actor could reconnect from multiple exit points — relevant to containment scope.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where ActionType == "LogonSuccess"
| where RemoteIP != "116.45.242.115" and RemoteIP != "::1" and RemoteIP != "" and RemoteIP != "-"
| project Timestamp, ActionType, LogonType, RemoteIP, RemoteIPType, IsLocalAdmin
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1133" height="649" alt="Flag8_SecondRemoteIP" src="https://github.com/user-attachments/assets/dd9c7993-c20b-4f08-a674-3e385611f8aa" />

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: The Command Burst</strong></summary>

### 🎯 Objective
Reconstruct the operator's initial recon commands, correctly separating them from OS/Edge first-run housekeeping.

### 📌 Finding
After ~90 seconds of Windows/Edge/OneDrive first-run noise, the operator opened `cmd.exe` and ran a clean, human-paced recon sequence.

### 🔍 Evidence

| Timestamp | Command |
|---|---|
| 01:30:09 | `cmd.exe` opens |
| 01:30:14 | `whoami` |
| 01:30:20 | `hostname` |
| 01:30:39 | `ipconfig /all` |
| 01:31:04 | `whoami /groups` |

### 💡 Why it matters
Confirms human, interactive operation (gaps of seconds-to-tens-of-seconds between commands) rather than scripted/automated execution.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where Timestamp >= datetime(2026-05-29T01:28:27Z)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1174" height="763" alt="Flag9_" src="https://github.com/user-attachments/assets/43fe300d-407a-4e77-89f2-f38688a60714" />

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Signal or Noise</strong></summary>

### 🎯 Objective
Assess a file deletion found inside the recon burst window.

### 📌 Finding
Not the operator. The deletion is OneDrive's own installer/updater self-cleanup.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Process | cmd.exe (spawned by explorer.exe) |
| Command | `/q /c del /q "C:\Users\m.reed\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"` and StandaloneUpdater equivalent |
| Context | Immediately follows `OneDriveSetup.exe /update /restart` calls |

### 💡 Why it matters
Demonstrates the importance of distinguishing machine housekeeping from operator activity before building a cover-up theory.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where InitiatingProcessAccountName =~ "m.reed"
| where ActionType == "FileDeleted"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1242" height="747" alt="Flag 10_" src="https://github.com/user-attachments/assets/e3f38088-fc93-4899-a925-f5e3061ff616" />

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Remote Share Enumeration</strong></summary>

### 🎯 Objective
Identify recon activity that extended beyond the local host.

### 📌 Finding
The operator queried the file server's shares directly.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Command | `net view \\NH-FS-01` |
| Timestamp | 2026-05-29T01:43:19.9477383Z |

### 💡 Why it matters
Confirms the operator was actively mapping accessible network resources beyond the compromised workstation.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "view"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1167" height="667" alt="Flag_11" src="https://github.com/user-attachments/assets/4d8662a0-8db1-43fb-a18b-7feacd0b0239" />

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: HR Group Enumeration</strong></summary>

### 🎯 Objective
Identify enumeration activity outside the account's authorized role.

### 📌 Finding
The account queried HR's domain security group — no legitimate basis under an IT Support role.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Command | `net  group "NH-HR-Users" /domain` |
| Timestamp | 2026-05-29T01:46:23.5812731Z |

### 💡 Why it matters
First clear evidence of role-boundary violation, foreshadowing the HR data access that follows.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "group" and ProcessCommandLine has "/domain"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1163" height="591" alt="Flag 12_" src="https://github.com/user-attachments/assets/425d8504-c5e6-4700-abce-33918c6dd498" />

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Out-of-Role File Access</strong></summary>

### 🎯 Objective
Identify the specific file accessed outside the account's authorized share.

### 📌 Finding
An HR access-request queue file was opened directly from the HR share over the network.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Command | `notepad  \\NH-FS-01\HR\2026-05\AccessRequests\access_request_queue_20260526.csv` |
| Timestamp | 2026-05-29T01:50:56.6178635Z |
| Filename | access_request_queue_20260526.csv |

### 💡 Why it matters
Confirms access to a share outside the account's role-matrix entitlement (IT share only).

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where FileName =~ "notepad.exe"
| where ProcessCommandLine has "\\\\NH-FS-01"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1168" height="560" alt="Flag 13" src="https://github.com/user-attachments/assets/0cfb4e77-a175-4336-be7a-c869bebf268f" />

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Staging Folder</strong></summary>

### 🎯 Objective
Identify where collected material was staged locally.

### 📌 Finding
HR files were copied/created into a dedicated local folder under the user's Documents directory.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Staging Folder | C:\Users\m.reed\Documents\SupportReview |
| Files Staged | access_request_queue_20260526.csv, access_review_notes_20260528.txt, employee_record_EMP-87291_20260527.txt |

### 💡 Why it matters
Confirms deliberate collection of multiple out-of-role files into one location prior to compression and exfiltration.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where InitiatingProcessAccountName =~ "m.reed"
| where ActionType == "FileCreated"
| where Timestamp > datetime(2026-05-29T01:50:56Z)
| summarize FileCount = count(), Files = make_set(FileName) by FolderPath
| order by FileCount desc
```

### 🖼️ Screenshot
<img width="1199" height="722" alt="Flag 14a" src="https://github.com/user-attachments/assets/dbc55b22-29e7-4f50-b9aa-9f549a9e5929" />


</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: The Archive</strong></summary>

### 🎯 Objective
Identify the compressed file created from the staged material.

### 📌 Finding
The staged folder was compressed into a single archive.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Archive | support_review_202605.zip |
| Location | C:\Users\m.reed\Documents\ |

### 💡 Why it matters
Marks the transition from collection to preparation for exfiltration.

### 🔧 KQL Query Used
Derived from Flag 14 DeviceFileEvents results — no separate query required.

### 🖼️ Screenshot
<img width="1153" height="475" alt="Flag 15_" src="https://github.com/user-attachments/assets/cc66014f-b502-4aa8-8363-54a92857c7a6" />

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Exfiltration Destination</strong></summary>

### 🎯 Objective
Determine where the archive was ultimately written.

### 📌 Finding
The archive was written to the attacker's own redirected local drive via the existing RDP session — no separate upload or cloud service involved.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Destination Path | \\tsclient\G\Temp\NimbusSupport |
| Mechanism | RDP client-drive redirection |

### 💡 Why it matters
Explains how data left the estate without triggering conventional network-based exfiltration detections.

### 🔧 KQL Query Used
Derived from Flag 14 DeviceFileEvents results — no separate query required.

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Persistence Check</strong></summary>

### 🎯 Objective
Determine whether the operator established any means of regaining access without the credential.

### 📌 Finding
No persistence was established. All scheduled-task activity observed belongs to native Windows/OneDrive sync tasks firing on normal triggers (e.g., `Logon`, `SyncFromCloud`, `KEYROAMING`), not operator-created entries.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Persistence Established? | No |
| Entries Found | Native Windows/OneDrive scheduled tasks (pre-existing, normal triggers) |

### 💡 Why it matters
Directly answers the "can they get back in without the password" question for containment planning.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where FileName in~ ("schtasks.exe","sc.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
```kql
DeviceEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where InitiatingProcessAccountName =~ "m.reed"
| where ActionType has_any ("ScheduledTask", "ServiceInstalled")
| project Timestamp, ActionType, AdditionalFields, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1182" height="418" alt="Flag 17_" src="https://github.com/user-attachments/assets/7d6a4149-dda6-4a04-8bac-125f8512696d" />


</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: File Server Access Method</strong></summary>

### 🎯 Objective
Determine whether the account ever directly accessed the file server.

### 📌 Finding
No — the account never executed anything or logged onto NH-FS-01. HR material was reached via a UNC path opened remotely from the workstation over SMB.

### 🔍 Evidence

| Field | Value |
|------|-------|
| File Server Logon/Execution? | No |
| Access Method | UNC path (`\\NH-FS-01\HR\...`) opened from NH-WKS-IT-01 via existing share permissions |

### 💡 Why it matters
Corrects the obvious-but-wrong assumption that the file server itself was compromised.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-fs-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-fs-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| project Timestamp, ActionType, LogonType, RemoteIP, DeviceName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1202" height="425" alt="Flag 18a_" src="https://github.com/user-attachments/assets/d459eeca-4ef7-4285-9850-06f5ef1a263d" />


</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: The Honest Read</strong></summary>

### 🎯 Objective
Provide the accurate characterization of the incident against the clinic's assumed "curious new starter" framing.

### 📌 Finding
This was an external account takeover conducted via Living-off-the-Land techniques, not insider curiosity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| What it was | External attacker, remote RDP access using a stolen/reused valid credential |
| What's absent | No malware or exploitation anywhere in the evidence; no local/console logon by Mason ever occurred |

### 💡 Why it matters
Prevents mischaracterization of an external intrusion as internal employee misconduct, which would materially change response and disclosure obligations.

### 🔧 KQL Query Used
None — synthesis of prior findings (Flags 6–18).

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Proving Credential Reuse</strong></summary>

### 🎯 Objective
Distinguish credential reuse from brute force using the logon evidence.

### 📌 Finding
3 failed attempts followed by 1 success, all within ~2 minutes — consistent with a small, known set of candidate passwords from breach data, not blind spraying.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Failures | 3 |
| Successes | 1 (then reused) |
| Window | 01:26:21 → 01:28:27 (2026-05-29) |
| Explanation | Low volume + fast success matches a curated credential from the Synthient/breach dataset, not brute-force iteration |

### 💡 Why it matters
Directly ties the intrusion mechanism back to the OSINT-identified breach exposure (Flag 5).

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where RemoteIP == "116.45.242.115"
| project Timestamp, ActionType, LogonType, RemoteIP
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: The Second Session</strong></summary>

### 🎯 Objective
Explain the ten-minute gap between the first and second command bursts.

### 📌 Finding
The operator reconnected from a different external IP.

### 🔍 Evidence

| Field | Value |
|------|-------|
| New RemoteIP | 45.131.194.61 |
| Timestamp | 2026-05-29T01:40:59.1133741Z |
| LogonType | RemoteInteractive |

### 💡 Why it matters
Confirms the operator switched exit addresses mid-intrusion rather than simply pausing — relevant to attribution and containment scope.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-29T01:38:00Z) .. datetime(2026-05-29T01:42:00Z))
| where AccountName has "reed"
| project Timestamp, ActionType, LogonType, RemoteIP
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Pre-Exfiltration Recon</strong></summary>

### 🎯 Objective
Identify the command proving premeditated exfiltration planning.

### 📌 Finding
The operator checked the RDP client-drive channel's availability before writing the archive to it.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Command | `net view \\tsclient` |
| Timestamp | 2026-05-29T01:56:12.3713693Z |

### 💡 Why it matters
Distinguishes deliberate, planned exfiltration from an opportunistic copy.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName startswith "nh-wks-it-01"
| where Timestamp between (datetime(2026-05-25) .. datetime(2026-05-30))
| where AccountName has "reed"
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "tsclient"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23 (IR1): First Containment Action</strong></summary>

### 🎯 Objective
Define the correct first containment step against the clinic's "reset the password" assumption.

### 📌 Finding
Disable the account and terminate active sessions — a password reset alone is insufficient.

### 🔍 Evidence

| Field | Value |
|------|-------|
| First Action | Disable `m.reed` account; terminate active RDP sessions to NH-WKS-IT-01 |
| Why reset alone fails | Credential was already circulating in breach/stuffing data prior to the incident; attacker demonstrated reconnection from multiple exit IPs, proving a single-password reset does not close re-entry paths |

### 💡 Why it matters
A reset-only response leaves active sessions and the underlying exposure vectors (cached document, breach data) unaddressed.

### 🔧 KQL Query Used
None — incident response synthesis.

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Data Obligation</strong></summary>

### 🎯 Objective
Determine what regulatory/legal obligation the exfiltrated data creates.

### 📌 Finding
Personal/employee data (HR access records and an individual employee record) was exfiltrated, triggering formal breach-notification obligations.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Data Type | Personal/employee data — access_request_queue CSV, employee_record_EMP-87291 |
| Obligation Triggered | Data breach assessment and notification requirements (e.g., HIPAA/state breach law), not a purely internal IT matter |

### 💡 Why it matters
Reframes the incident from an internal access-control issue into a compliance and legal disclosure event.

### 🔧 KQL Query Used
None — derived from Flag 14 file contents.

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- No monitoring in place for internal documents leaking into public document caches (Artefact 03 was indexed nearly a month before the intrusion with no apparent alert).
- No detection for RDP client-drive-redirection-based file transfers — a significant blind spot since it bypasses conventional network-based exfiltration monitoring entirely.
- No control preventing reuse of breach-exposed passwords for domain accounts (no apparent password-reuse screening against known-breach corpora).
- Shared department workstations combined with rapid onboarding created broad, under-reviewed access exposure during the staffing surge.

### Recommendations
- Immediately rotate `m.reed`'s credentials and audit for reuse elsewhere in the environment; disable and review the account pending full investigation.
- Restrict or monitor RDP client-drive redirection on IT/administrative endpoints, particularly the designated remote-support host.
- Screen new and existing domain credentials against known breach-exposure datasets; enforce unique, non-reused passwords.
- Remove/prevent internal reference documents from public indexing; review other internal documentation for similar exposure.
- Reassess access reviews and onboarding controls to keep pace with rapid hiring — access boundaries should not lag behind headcount growth.

---

## 🧾 Final Assessment

This was a low-complexity, high-impact intrusion: an external actor exploiting publicly available personal information, a reused breached credential, and a carelessly exposed internal document to gain valid remote access to a Nimbus Health IT workstation. No exploitation or malware was required at any stage — the entire operation relied on legitimate tools and a legitimate (if stolen) credential, making it difficult to catch with signature-based defenses alone. The attacker moved deliberately: reconnaissance, role-boundary violation into HR data, staging, and exfiltration via an RDP channel that evades typical network-based detection. The clinic's instinct to treat this as a "curious new starter" is not supported by the evidence — every access originated remotely, from credentials the attacker already possessed. The exposure of personal/employee data elevates this beyond an IT hygiene issue into a compliance and breach-notification matter.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting in the law-cyber-range Sentinel workspace
- Techniques mapped directly to MITRE ATT&CK
- OSINT artefacts (Flags 1–5) were resolved prior to any telemetry query, per hunt brief instructions
- All telemetry scoped strictly to NH-WKS-IT-01, 2026-05-25 → 2026-05-30, account `m.reed`

---
