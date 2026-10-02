# **WINDOWS EVENT LOG FORENSICS & INCIDENT RESPONSE**


**Advanced digital forensics investigation simulating real-world security breach scenario**

[![Lab Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)]()
[![Institution](https://img.shields.io/badge/Institution-HOWEST-blue?style=flat-square)]()
[![Course](https://img.shields.io/badge/Course-Cyber%20Security%20Essentials-orange?style=flat-square)]()
[![Module](https://img.shields.io/badge/Module-8-red?style=flat-square)]()

## Contents

- [Academic Context](#academic-context)
- [Lab Overview](#lab-overview)
- [Learning Objectives](#learning-objectives)
- [Investigation Phases](#investigation-phases)
- [Investigation Workflow](#investigation-workflow)
- [Incident Response Framework Application](#incident-response-framework-application)
- [Key Concepts and Learning Outcomes](#key-concepts--learning-outcomes)
- [Practical Skills Demonstrated](#practical-skills-demonstrated)
- [Real-World Applications](#real-world-applications)
- [Frameworks and Standards Applied](#frameworks--standards-applied)
- [Legal and Ethical Considerations](#legal--ethical-considerations)
- [Additional Resources](#additional-resources)
- [Lab Completion Summary](#lab-completion-summary)
- [Author](#author)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## 🎓 Academic Context

**Institution:** Howest University of Applied Sciences (Belgium)  
**Course:** Cyber Security Essentials  
**Module:** Module 8 - Windows Events  
**Lab Type:** Incident Response & Digital Forensics  
**Date:** December 2025  
**Student:** Muhammad Izaz Haider

---

## 📋 Lab Overview

This lab simulates a **post-breach investigation** where a Windows endpoint has been compromised. As a security analyst, you must analyze raw Windows Security Event Logs to reconstruct the complete attack timeline, identify the threat actor, and document evidence for incident response.

### Scenario

> *"A Windows system has been compromised. The security team has extracted the Security Event Log file (SecurityLog.evtx) before the attacker could cover their tracks. Your mission: reconstruct the entire attack from initial access to data exfiltration using only the Windows Event Viewer."*

---

## 🎯 Learning Objectives

### Digital Forensics
- Analyze Windows Security Event Logs (.evtx files)
- Distinguish between legitimate and malicious user activity
- Reconstruct attack timelines using log correlation
- Extract Indicators of Compromise (IOCs) from event metadata

### Incident Response
- Apply NIST 6-phase IR lifecycle
- Classify incidents using US-CERT and ENISA taxonomies
- Document evidence chain for legal/compliance purposes
- Make strategic IR decisions under pressure (extortion scenarios)

### Threat Hunting
- Identify privilege escalation techniques
- Detect lateral movement patterns
- Recognize persistence mechanisms (backdoor accounts)
- Trace network attribution data

---

# 🔍 INVESTIGATION PHASES

## Phase 1: Baseline Establishment

### Objective
Identify the **legitimate user** of the system to distinguish normal activity from attacker behavior.

### Methodology

**Event ID:** 4624 (Successful Logon)

**Target Time:** Early morning (first interactive logon of the day)

**Key Fields to Analyze:**
- **Logon Type:** Look for Type 2 (Interactive - physical keyboard)
- **Subject vs. New Logon:** 
  - Subject = System process handling the login
  - New Logon = **Actual user** logging in
- **Security ID (SID):** Unique identifier for the user account

### Analysis Checklist

```
□ Located Event ID 4624 with Logon Type 2
□ Identified Account Name under "New Logon" section
□ Extracted Security ID (format: S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXX)
□ Verified this is the first interactive login of the day
```

### Critical Finding

✅ **Baseline user identified** - All subsequent activity will be compared against this baseline.

---

## Phase 2: Breach Detection

### Objective
Identify **unauthorized system changes** indicating compromise.

### Methodology

**Event ID:** 4720 (User Account Created)

**Target Time:** Mid-morning (after legitimate user logged in)

**Key Fields to Analyze:**
- **Subject:** Who created the account? (Check if it's the legitimate user or SYSTEM)
- **New Account Name:** What is the name of the suspicious account?
- **Security ID:** New SID assigned to the created account

**Event ID:** 4732 (Member Added to Security-Enabled Local Group)

**Key Fields:**
- **Group Name:** Was the account added to "Administrators"?
- **Member SID:** Does it match the newly created account?

### Attack Pattern Recognition

This sequence indicates a **Persistence** technique:

```
Timeline of Compromise:
─────────────────────────────────────────────────
11:15:00 → Event 4720 (Account Created)
11:15:01 → Event 4722 (Account Enabled)
11:15:02 → Event 4724 (Password Reset)
11:15:03 → Event 4732 (Added to Administrators)
─────────────────────────────────────────────────
```

### Analysis Checklist

```
□ Located Event ID 4720 (account creation)
□ Verified account was enabled immediately after creation
□ Confirmed account was added to Administrators group
□ Documented new account name and SID
□ Classified as Privilege Escalation + Persistence
```

### MITRE ATT&CK Mapping

**Tactic:** Persistence (TA0003)  
**Technique:** Create Account: Local Account (T1136.001)  
**Sub-Technique:** Add user to Administrators group for elevated privileges

---

## Phase 3: Attack Execution

### Objective
Determine **how the attacker accessed** the compromised system.

### Methodology

**Event ID:** 4624 (Successful Logon)

**Target Time:** Shortly after account creation (~11:36)

**Target Account:** The newly created malicious account

**Critical Analysis: Logon Type Classification**

| Logon Type | Description | Attack Context |
|------------|-------------|----------------|
| **2** | Interactive | Local keyboard/screen access |
| **3** | Network | File share or printer access |
| **10** | RemoteInteractive | **Remote Desktop Protocol (RDP)** |

### Network Forensics

**Key Fields in Event 4624:**
- **Network Information Section:**
  - Workstation Name
  - **Source Network Address** (Attacker's IP)
  - Source Port
- **Detailed Authentication:**
  - Logon Process (e.g., User32, NtLmSsp)
  - Authentication Package (NTLM, Kerberos)

### Analysis Checklist

```
□ Filtered Event ID 4624 for malicious account name
□ Identified Logon Type 10 (RDP) and/or Type 3 (Network)
□ Extracted Source Network Address (attacker's IP)
□ Noted timestamp of first malicious login
□ Documented authentication method (NTLM vs Kerberos)
```

### Attack Vector Identification

✅ **Primary Vector:** Remote Desktop Protocol (RDP)  
✅ **Secondary Vector:** Network share access (SMB/CIFS)  
✅ **Attribution:** External IP address identified

### MITRE ATT&CK Mapping

**Tactic:** Initial Access (TA0001) / Lateral Movement (TA0008)  
**Technique:** Remote Services: Remote Desktop Protocol (T1021.001)  
**Technique:** Remote Services: SMB/Windows Admin Shares (T1021.002)

---

## Phase 4: Lateral Movement & Exfiltration

### Objective
Trace attacker's **post-exploitation activity** and identify data theft.

### Methodology

**Event ID:** 4648 (Logon Attempted Using Explicit Credentials)

**What This Means:**
- User A is logged in
- User A attempts to access a resource **as User B**
- Common in:
  - `runas` command
  - Mapping network drives with alternate credentials
  - **Lateral movement to another server**

**Key Fields:**
- **Subject:** Currently logged-in user (the attacker's account)
- **Account Whose Credentials Were Used:** Different account (e.g., "guest")
- **Target Server Name:** Remote system being accessed
- **Network Address:** Destination IP

**Event ID:** 5140 (Network Share Object Accessed)

**What This Means:**
- A file share (e.g., `\\server\backup`) was accessed
- Useful for identifying data exfiltration attempts

### Analysis Checklist

```
□ Located Event 4648 within ~1 minute of malicious login
□ Identified Target Server Name (storage infrastructure)
□ Noted which credentials were used (guest, service account, etc.)
□ Checked for Event 5140 (share access) to confirm file operations
□ Documented accessed share paths
```

### Evidence of Exfiltration

✅ **Target Server:** Storage infrastructure identified  
✅ **Method:** Explicit credential logon to remote server  
✅ **Timeline:** Occurred within minutes of initial access  
✅ **Risk:** Potential data theft confirmed

### MITRE ATT&CK Mapping

**Tactic:** Lateral Movement (TA0008)  
**Technique:** Use Alternate Authentication Material (T1550)  
**Tactic:** Exfiltration (TA0010)  
**Technique:** Exfiltration Over SMB (T1048.002)

---

# 🧪 INVESTIGATION WORKFLOW

## Tools Required

- **Windows Event Viewer** (built-in to Windows)
- **SecurityLog.evtx** (provided evidence file)

## Step-by-Step Process

### 1. Load Evidence File

```
1. Open Event Viewer (eventvwr.msc)
2. Right-click "Windows Logs" → "Security"
3. Select "Open Saved Log..."
4. Browse to SecurityLog.evtx
5. Click "Open"
```

### 2. Create Custom Filters

**Filter by Event ID:**
```
<QueryList>
  <Query Id="0" Path="file://C:\Path\To\SecurityLog.evtx">
    <Select Path="Security">*[System[(EventID=4624)]]</Select>
  </Query>
</QueryList>
```

**Filter by Time Range:**
```
1. Right-click log → "Filter Current Log"
2. Set "Logged:" to "Custom range"
3. Enter start/end times based on investigation timeline
```

### 3. Event Analysis Sequence

```
STEP 1: Identify baseline user
   └─> Filter Event 4624 + Logon Type 2
   └─> Extract legitimate user SID

STEP 2: Detect persistence mechanism
   └─> Filter Event 4720 (User Created)
   └─> Filter Event 4732 (Group Membership)
   └─> Extract malicious account name + SID

STEP 3: Trace attack execution
   └─> Filter Event 4624 for malicious account
   └─> Identify Logon Type 3 + 10
   └─> Extract Source Network Address (IP)

STEP 4: Map lateral movement
   └─> Filter Event 4648 (Explicit Credentials)
   └─> Extract Target Server Name
   └─> Document exfiltration evidence
```

---

# 📊 INCIDENT RESPONSE FRAMEWORK APPLICATION

## NIST 6-Phase Lifecycle

### 1. Preparation
- **Lab Context:** Secure forensic workstation prepared
- **Real-World:** IR team trained, tools ready, playbooks documented

### 2. Detection & Analysis (This Lab)
- **Event Log Analysis:** Identified malicious activity via Event 4624, 4720, 4732
- **IOC Extraction:** Malicious account name, attacker IP, target server
- **Attack Reconstruction:** Complete timeline from breach to exfiltration

### 3. Containment
- **Short-term:** Disable malicious account, block attacker IP
- **Long-term:** Patch RDP vulnerabilities, enforce MFA

### 4. Eradication
- **Actions:** Remove malicious account, clear persistence mechanisms
- **Verification:** Scan for additional backdoors, rootkits

### 5. Recovery
- **Actions:** Restore systems from clean backups, monitor for re-infection
- **Validation:** Verify attacker no longer has access

### 6. Lessons Learned
- **Documentation:** Complete incident report with timeline
- **Improvements:** Enhance logging, deploy EDR, network segmentation

---

## US-CERT Attack Vector Taxonomy

**Classification of This Incident:**

| Category | Sub-Category | Evidence |
|----------|--------------|----------|
| **External/Removable Media** | ❌ Not applicable | No USB/CD activity |
| **Attrition** | ❌ Not applicable | No brute force detected |
| **Web** | ❌ Not applicable | No web-based attack |
| **Email** | ⚠️ Unknown | Email not analyzed in this lab |
| **Impersonation** | ⚠️ Possible | Attacker may have phished credentials |
| **Improper Usage** | ❌ Not applicable | Legitimate user not at fault |
| **Loss/Theft** | ❌ Not applicable | No physical device loss |
| **Other** | ✅ **Most Likely** | Initial access method unclear |

**Conclusion:** Attack vector classified as **Unknown** - RDP access confirmed, but **how credentials were obtained** is not visible in logs.

---

## ENISA Incident Classification

**Primary Category:** Information Content Security

**Justification:**
- **Unauthorized Access:** Malicious account created and used
- **Unauthorized Modification:** System configuration changed (new admin user)
- **Information Leak:** Potential data exfiltration to storage server

**Severity Level:** High

**Impact Areas:**
- **Confidentiality:** Compromised (data potentially stolen)
- **Integrity:** Compromised (unauthorized account created)
- **Availability:** Minimal impact (system still operational)

---

# 🎓 KEY CONCEPTS & LEARNING OUTCOMES

## Understanding Logon Types

| Type | Name | Description | Typical Use | Attack Relevance |
|------|------|-------------|-------------|------------------|
| 2 | Interactive | Keyboard/screen | User at console | Legitimate user baseline |
| 3 | Network | File/printer share | SMB, CIFS | Lateral movement, exfiltration |
| 4 | Batch | Scheduled task | Automated jobs | Persistence mechanism |
| 5 | Service | Windows service | Background processes | Privilege escalation |
| 7 | Unlock | Screen unlock | Resume session | Session hijacking |
| 8 | NetworkCleartext | IIS Basic Auth | Web login | Credential theft |
| 9 | NewCredentials | RunAs, net use | Alternate creds | Lateral movement |
| 10 | RemoteInteractive | RDP | Remote Desktop | **Primary attack vector** |
| 11 | CachedInteractive | Cached domain | Offline login | Credential harvesting |

---

## Subject vs. New Logon (Event 4624)

### Common Confusion

```
Event ID 4624 - Successful Logon

Subject:
  Security ID:      S-1-5-18 (SYSTEM)
  Account Name:     COMPUTER-NAME$
  Account Domain:   WORKGROUP
  Logon ID:         0x3E7

New Logon:
  Security ID:      S-1-5-21-XXXXX-XXXXX-XXXXX-1000
  Account Name:     User
  Account Domain:   COMPUTER-NAME
  Logon ID:         0x13C89
```

**❌ WRONG:** The user is "SYSTEM"  
**✅ CORRECT:** The user is "User" (SID ending in -1000)

**Explanation:**
- **Subject** = The Windows component that **processed** the login (e.g., winlogon.exe running as SYSTEM)
- **New Logon** = The **actual user account** that was logged in

---

## Security Identifier (SID) Structure

```
S-1-5-21-705428713-1283917362-25449821-1000
│ │ │  │                                 └─> RID (Relative Identifier)
│ │ │  └─────────────────────────────────────> Domain/Computer Identifier
│ │ └────────────────────────────────────────> NT Authority
│ └──────────────────────────────────────────> Revision (always 1)
└────────────────────────────────────────────> SID Identifier Authority
```

**Common RIDs:**
- **500** → Local Administrator account
- **501** → Guest account
- **1000+** → User-created accounts

**Forensic Value:**
- SIDs **never change** (even if username is changed)
- Use SID to **track the same user** across different events

---

## Event ID Reference (Security Log)

| Event ID | Description | Forensic Value |
|----------|-------------|----------------|
| **4608** | Windows Starting Up | Establishes system boot timeline |
| **4624** | Successful Logon | Primary event for tracking access |
| **4625** | Failed Logon | Detects brute force attempts |
| **4648** | Logon Using Explicit Credentials | Lateral movement, privilege escalation |
| **4672** | Special Privileges Assigned | Admin/SYSTEM privilege use |
| **4720** | User Account Created | Persistence mechanism detection |
| **4722** | User Account Enabled | Account activation |
| **4724** | Password Reset Attempt | Credential tampering |
| **4732** | Member Added to Group | Privilege escalation |
| **4740** | Account Lockout | Failed authentication tracking |
| **5140** | Network Share Accessed | Data exfiltration evidence |
| **5145** | Detailed File Share Audit | Specific file access tracking |
| **1102** | Audit Log Cleared | Anti-forensics / log tampering |

---

# 🛠️ Practical Skills Demonstrated

## Digital Forensics

✅ **Log Analysis:**
- Filtered 1000+ events to identify 5-10 critical incidents
- Correlated multiple event types to build cohesive timeline
- Distinguished noise from signal (service accounts vs. malicious users)

✅ **Artifact Recovery:**
- Extracted IOCs: account names, SIDs, IP addresses, server names
- Documented chain of custody for evidence
- Preserved log integrity (read-only analysis)

## Incident Response

✅ **Attack Reconstruction:**
- Mapped complete kill chain from initial access to exfiltration
- Identified MITRE ATT&CK TTPs (Tactics, Techniques, Procedures)
- Classified incident severity using industry frameworks

✅ **Strategic Decision-Making:**
- Triaged extortion threat scenarios
- Prioritized containment actions
- Balanced business impact vs. security response

## Threat Hunting

✅ **Pattern Recognition:**
- Identified anomalous logon types (Type 10 from external IP)
- Detected privilege escalation patterns (rapid account creation + admin group addition)
- Recognized lateral movement indicators (Event 4648 to storage server)

---

# 🏆 Real-World Applications

## SOC Analyst Use Cases

**Scenario 1: Alert Triage**
```
SIEM Alert: "New local admin account created"
└─> Filter Event 4720 + 4732
└─> Verify if change request exists
└─> If unauthorized → Escalate to Tier 2
```

**Scenario 2: Compromised Credential Investigation**
```
Threat Intel: "IP 192.168.x.x linked to APT group"
└─> Filter Event 4624 by Source Network Address
└─> Identify all accounts accessed from that IP
└─> Force password reset + MFA enrollment
```

**Scenario 3: Insider Threat Detection**
```
HR Notification: "Employee terminated today"
└─> Monitor Event 4624 for terminated user SID
└─> If logon detected after termination → Account still active
└─> Disable account immediately
```

---

## Incident Response Scenarios

### Scenario A: Ransomware Outbreak

**Log Analysis Focus:**
- Event 4720: Were new service accounts created? (persistence)
- Event 4624 Type 3: Lateral movement to file servers
- Event 5145: Mass file access (encryption activity)

### Scenario B: Data Breach Investigation

**Log Analysis Focus:**
- Event 4624 Type 10: Unauthorized RDP access
- Event 4648: Lateral movement to database servers
- Event 5140: Network share access to sensitive directories

### Scenario C: Privilege Escalation

**Log Analysis Focus:**
- Event 4672: Who received special privileges?
- Event 4732: Who was added to Domain Admins?
- Event 4720: Were new privileged accounts created?

---

# 📚 Frameworks & Standards Applied

## MITRE ATT&CK

**Tactics Identified:**
- TA0001: Initial Access (RDP compromise)
- TA0003: Persistence (local account creation)
- TA0004: Privilege Escalation (admin group membership)
- TA0008: Lateral Movement (explicit credentials to storage server)
- TA0010: Exfiltration (SMB share access)

**Techniques Identified:**
- T1078: Valid Accounts (compromised credentials)
- T1136.001: Create Account - Local
- T1021.001: Remote Desktop Protocol
- T1021.002: SMB/Windows Admin Shares
- T1550: Use Alternate Authentication Material

---

## NIST Cybersecurity Framework

**Functions Applied:**

1. **Identify:** Baseline system activity established
2. **Protect:** N/A (post-breach analysis)
3. **Detect:** Malicious activity identified via log analysis ✅
4. **Respond:** IR procedures followed ✅
5. **Recover:** Not covered in this lab (would involve system restoration)

---

## GDPR Implications

**Data Breach Notification Requirements:**

If this were a real incident involving personal data:

- **72-hour rule:** Must notify supervisory authority within 72 hours of **becoming aware** (not occurrence)
- **Individual notification:** Required if "high risk" to data subjects
- **Documentation:** Must record all breaches (even if not reported)

**Data Processor Responsibilities:**
- Notify data controller "without undue delay"
- Assist with impact assessment (DPIA)
- Cooperate with investigations

---

# ⚠️ Legal & Ethical Considerations

## Educational Use Only

**This lab demonstrates authorized security analysis techniques.**

### Legal Warnings

🚨 **Unauthorized access to computer systems is illegal under:**
- **CFAA** (Computer Fraud and Abuse Act) - USA
- **Computer Misuse Act 1990** - UK
- **Directive 2013/40/EU** - European Union
- **Local cybercrime laws** in your jurisdiction

### Authorized Use Cases ONLY

✅ **Permitted:**
- Academic coursework in controlled VM environments
- Authorized penetration testing with written contracts
- Incident response for your own organization
- Security research on your own devices
- SOC analyst duties within scope of employment

❌ **Prohibited:**
- Analyzing logs from systems you don't own/control
- Accessing other people's computers without permission
- Using these techniques for stalking/harassment
- Sharing extracted evidence publicly (privacy violations)

### Best Practices

1. **Always get written authorization** before analyzing logs
2. **Respect privacy** - logs may contain PII (Personally Identifiable Information)
3. **Maintain confidentiality** - never share real evidence publicly
4. **Follow chain of custody** - document all analysis steps
5. **Know your legal obligations** - GDPR, HIPAA, PCI-DSS compliance

---

# 📚 Additional Resources

## Official Documentation

### Windows Event Logging
- [Microsoft Security Auditing Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Windows 10/11 Security Event Descriptions](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Advanced Security Audit Policy Settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)

### Incident Response
- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [FIRST CSIRT Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)

### Threat Intelligence
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [US-CERT Alert Categories](https://www.cisa.gov/uscert/ncas/alerts)
- [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends)

---

## Training & Certifications

**Recommended next steps:**

### Digital Forensics
- **GIAC Certified Forensic Analyst (GCFA)**
- **EnCase Certified Examiner (EnCE)**
- **CHFI (Computer Hacking Forensic Investigator)**

### Incident Response
- **GIAC Certified Incident Handler (GCIH)**
- **ECIH (EC-Council Certified Incident Handler)**
- **CSIH (Certified Security Incident Handler)**

### SOC Analysis
- **GIAC Security Operations Certified (GSOC)**
- **Splunk Certified User**
- **Microsoft Security Operations Analyst (SC-200)**

---

## Useful Tools

| Tool | Purpose | Download |
|------|---------|----------|
| **Event Log Explorer** | Advanced .evtx analysis | https://eventlogxp.com/ |
| **Chainsaw** | Rapid event log hunting | https://github.com/WithSecureLabs/chainsaw |
| **Hayabusa** | Timeline generation | https://github.com/Yamato-Security/hayabusa |
| **DeepBlueCLI** | PowerShell threat hunting | https://github.com/sans-blue-team/DeepBlueCLI |
| **LogParser** | SQL-like log queries | https://www.microsoft.com/en-us/download/details.aspx?id=24659 |

---

# 🏆 Lab Completion Summary

## Skills Acquired

### Technical Skills
✅ Windows Event Viewer navigation and filtering  
✅ Security Event Log (.evtx) analysis  
✅ Event ID correlation across timelines  
✅ SID and RID forensic interpretation  
✅ Logon Type classification (2, 3, 10)  
✅ Network attribution (IP extraction)  
✅ IOC (Indicator of Compromise) extraction  

### Analytical Skills
✅ Attack timeline reconstruction  
✅ Baseline vs. anomaly identification  
✅ Lateral movement pattern recognition  
✅ Persistence mechanism detection  
✅ Evidence documentation for legal proceedings  

### Framework Knowledge
✅ NIST 6-phase Incident Response lifecycle  
✅ MITRE ATT&CK tactics and techniques  
✅ US-CERT attack vector taxonomy  
✅ ENISA incident classification  
✅ GDPR breach notification requirements  

---

## Evidence Recovered

| Artifact Type | Description |
|---------------|-------------|
| **Legitimate User** | Baseline account identified via Logon Type 2 |
| **Malicious Account** | Backdoor admin account created by attacker |
| **Attack Vector** | RDP (Logon Type 10) from external IP address |
| **Persistence** | Local admin account creation (Event 4720 + 4732) |
| **Lateral Movement** | Explicit credential use to storage server (Event 4648) |
| **Exfiltration Target** | Storage infrastructure identified |

---

## Investigation Timeline

```
04:41:45 → Legitimate user logs in (Logon Type 2)
   ↓
09:13:15 → Legitimate user logs off
   ↓
11:15:00 → 🚨 BREACH DETECTED
           ├─> Event 4720: Malicious account created
           ├─> Event 4732: Account added to Administrators
           └─> Persistence mechanism established
   ↓
11:36:00 → 🚨 ATTACK EXECUTION
           ├─> Event 4624 Type 10: RDP login from external IP
           └─> Event 4624 Type 3: Network share access
   ↓
11:37:00 → 🚨 DATA EXFILTRATION
           └─> Event 4648: Lateral movement to storage server
```

---

## Metrics

| Metric | Value |
|--------|-------|
| **Event IDs Analyzed** | 4608, 4624, 4625, 4648, 4720, 4732, 5140 |
| **Total Log Entries Reviewed** | 1000+ events |
| **Critical Events Identified** | 8 key incidents |
| **Attack Phases Mapped** | 5 (Access, Persistence, Escalation, Movement, Exfiltration) |
| **IOCs Extracted** | 6 artifacts (account names, IPs, server names) |
| **MITRE Techniques Identified** | 5 techniques across 4 tactics |
| **Investigation Time** | ~2 hours (hands-on lab) |

---

## 👤 Author

**Muhammad Izaz Haider**  
Cybersecurity Student @ Howest University of Applied Sciences  
Junior DevSecOps & Ai Security Engineer 
Focus: Penetration Testing · OSINT · DevSecOps



- 📧 Contact: mizazhaiderceh@gmail.com 
- 💼 LinkedIn: https://www.linkedin.com/in/muhammad-izaz-haider-091639314
- 🐙 GitHub: github.com/mizazhaider-ceh


---

## Acknowledgments

**Course Instructor:** Kurt Schoenmaekers  
**Institution:** HOWEST Hogeschool West-Vlaanderen  
**Lab Environment:** Windows Event Viewer + SecurityLog.evtx  
**Frameworks:** NIST, MITRE, US-CERT, ENISA

---

**Lab Status:** ✅ **COMPLETED**  
**Date:** December 11, 2025  
**Total Lab Time:** ~2 hours

---

## 📄 License

This educational project documentation is shared for academic and learning purposes.

**Usage:**
- ✅ Free to reference for educational purposes
- ✅ May be used as study material
- ✅ Can be adapted for similar coursework
- ❌ Do not use for unauthorized system access
- ❌ Do not share extracted evidence publicly

---

## ⭐ Repository Statistics

![GitHub Stars](https://img.shields.io/github/stars/mizazhaider-ceh/windows-events-forensics-incident-response-lab?style=social)
![GitHub Forks](https://img.shields.io/github/forks/mizazhaider-ceh/windows-events-forensics-incident-response-lab?style=social)

**If this helped you learn Windows Event Log forensics, consider giving it a ⭐!**
