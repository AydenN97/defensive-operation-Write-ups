***Title:*** Challenge 1 Write-Up: New Hire Old Artifacts


***Scenario Overview:*** As a SOC Analyst at a Managed Security Service Provider (MSSP), I was tasked with investigating a newly onboarded customer, Widget LLC, whose endpoints had recently been integrated into our Splunk environment.
During onboarding, it was discovered that an endpoint assigned to a newly hired Financial Analyst had operated for an extended period with its endpoint security protections disabled. Because of this security gap, the endpoint required further investigation to determine whether any malicious activity had occurred while it was unprotected.

***Objective:*** Analyze the endpoint's Windows event logs in Splunk to identify indicators of compromise (IOCs), determine whether malicious activity occurred, and identify any findings that should be reported to the customer.

***Background:***

**Room Link:** [https://tryhackme.com/room/newhireoldartifacts.com]

**Difficulty:** 🟡 Medium

**Category:** Blue Team / SIEM / Endpoint Investigation


## Start of Investigation ##


***Alert Intake***

The logs required for this investigation had already been ingested into Splunk. This investigation focuses on log analysis, event correlation, and threat hunting using Splunk's Search & Reporting application.


***1. Initial Triage***

The endpoint contained the following Windows log sources:
- Application
- Microsoft Sysmon Operational
- Security
- System
Initial Information

The initial indicator provided to us was that concluded that a malware- Web Browser Password Viewer had executed on the endpoint. We will want to look closely for execution of malicious and abnormal executables and the presence of unsual .dlls, .bats, etc. 
Because process execution is best analyzed using Sysmon Process Creation events (Event ID 1), Sysmon was selected as the primary log source. We will review the results by command line. 

### Splunk Query
```spl
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| stats count by CommandLine
```

Reviewing Sysmon Event ID 1 process creation logs revealed the execution of a suspicious executable named **11111.exe**. The binary immediately stood out because it executed from the user's temporary directory using a randomly generated filename, both of which are common indicators of malicious activity.
Several characteristics made this process stand out:
- The executable had a random, non-descriptive filename.
- It executed from the user's Temp directory, a location commonly abused by malware.
- The filename did not resemble any legitimate Windows or business application.
- The process hash was extracted from the Sysmon event.
- MD5: 7165E9D7456520D1F1644AA26DA7C423

The executable's MD5 hash was extracted from the Sysmon event and submitted to VirusTotal for reputation analysis. VirusTotal identified the sample as malicious, with 54 of 71 security vendors detecting it as malware, confirming that it was the Web Browser Password Viewer referenced in the scenario.

***1A.Threat Intelligence:***

VirusTotal identified the file as malicious, with 54 of 71 security vendors detecting it as malware.
The reputation results confirmed that the executable was the Web Browser Password Viewer referenced in the investigation scenario.

<img width="904" height="307" alt="Image" src="https://github.com/user-attachments/assets/d8c7ce98-f55e-4b70-baa8-376868c55bc0" /> 
	
	*11111.exe Threat Intelligence lookup*



***2.Threat Hunting:***

While continuing to review the process creation events, another alert indicated that additional suspicious binaries had been executed from the same temporary directory:
- C:\Users\Finance01\AppData\Local\Temp

Reviewing the command-line history revealed several additional suspicious files:
- fj4ghga23_fsa.txt
- IonicLarge.exe
- PalitExplorer.exe

These filenames appeared highly unusual and warranted additional investigation.


***3.Network Activity Analysis:***

During the investigation, it was noted that one of the identified binaries established an outbound connection to a known malicious IP address.
To determine which executable initiated the network connection, the investigation was narrowed to the suspicious binary IonicLarge.exe.

### Splunk Query
```spl 
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="C:\Users\Finance01\AppData\Local\Temp\IonicLarge.exe"
```

The logs showed that IonicLarge.exe was the only suspicious executable generating outbound network connections.

The destination IP address was:
- 2[.]56[.]59[.]42

The IP address was submitted to VirusTotal, where it was identified as malicious by 14 security vendors, further strengthening the evidence that the endpoint had executed malicious software capable of communicating with external infrastructure.




***4.Registry Modification Analysis:***

The investigation then shifted toward identifying potential persistence mechanisms and defense-evasion techniques used by the suspicious executable.

Because **Sysmon Event ID 13** logs registry value modifications, the investigation was narrowed to registry activity associated with **IonicLarge.exe**.

### Findings

Filtering Sysmon events for **Event ID 13** revealed that `IonicLarge.exe` attempted to modify the following Windows Defender registry key:

- HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

<img width="509" height="212" alt="Image" src="https://github.com/user-attachments/assets/164b98e5-a53e-4b76-899e-fdbc2961723d" />


***5.Defense Evasion*** 

On Windows systems, process termination can be investigated by looking for the use of taskkill.exe, particularly commands using the /IM parameter to terminate processes by image name.

Because Sysmon Event ID 1 records process creation, the investigation focused on process creation events and command-line activity.

Splunk Query
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by Message

Reviewing the resulting command-line history revealed the execution of taskkill.exe with the /IM parameter:

taskkill /im "WvmIOrcfsuILdX6SNwIRmGOJ.exe"
taskkill /im "phcIAmLJMAIMSa9j9MpgJo1m:.exe"

The randomly generated names of the targeted executables, combined with evidence that the associated binaries were subsequently deleted, were highly suspicious.

This activity is consistent with an attempt to terminate malicious processes and remove associated artifacts, potentially to conceal activity and complicate incident response and forensic analysis.

Screenshots: 
<img width="529" height="283" alt="Image" src="https://github.com/user-attachments/assets/bf911c00-0174-4ecd-a51e-51b94e4cec5a" />

<img width="465" height="287" alt="Image" src="https://github.com/user-attachments/assets/f89643b6-1d80-40ab-84df-c6ce0869916e" />


*** Defense Evasion *** 

The investigation indicated that the attacker executed several commands within a PowerShell session to modify the behavior of Microsoft Defender. The objective was to identify these commands within the endpoint telemetry and determine how the attacker attempted to weaken security protections.

Because Sysmon Event ID 1 records process creation and command-line activity, the investigation focused on process creation events and filtered for PowerShell executions.

Splunk Query
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by CommandLine
| search CommandLine="*powershell*"

Reviewing the resulting command-line activity revealed several PowerShell commands using WMIC to interact with the Windows Defender MSFT_MpPreference configuration:

/C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147735503 ThreatIDDefaultAction_Actions=6 Force=True
/C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737007 ThreatIDDefaultAction_Actions=6 Force=True
/C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737010 ThreatIDDefaultAction_Actions=6 Force=True
/C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True

Researching the command, it can be concluded that it modified Microsoft Defender's response configuration for specific threat IDs, indicating an attempt to alter how Defender handled detected threats.


*****  Conclusion  *****

The investigation identified multiple indicators of compromise and behaviors consistent with a compromised Windows endpoint. Analysis of Sysmon process creation, network, and registry activity revealed evidence of malicious execution, credential theft, command-and-control communication, defense evasion, and attempts to remove evidence of the activity.

Key Findings
Identified the execution of a Web Browser Password Viewer, indicating potential credential theft activity.
Identified multiple suspicious binaries executing from the user's temporary directory, including IonicLarge.exe and PalitExplorer.exe.
Validated a suspicious executable hash through VirusTotal, which was detected as malicious by 54 of 71 security vendors.
Identified an outbound connection from IonicLarge.exe to 2[.]56[.]59[.]42, which was identified as malicious by 14 security vendors.
Discovered registry modifications targeting HKLM\SOFTWARE\Policies\Microsoft\Windows Defender, indicating an attempt to weaken endpoint security protections.
Identified PowerShell and WMIC commands modifying Microsoft Defender threat-response configurations.
Observed taskkill.exe being used to terminate suspicious processes, followed by deletion of associated binaries, indicating potential attempts to remove evidence and complicate forensic analysis.

Taken together, these findings provide strong evidence that the endpoint was compromised and that the attacker attempted to maintain execution, communicate with external infrastructure, weaken security controls, and remove artifacts associated with the intrusion.

MITRE ATT&CK Techniques

The observed activity can be mapped to several MITRE ATT&CK tactics and techniques:

Tactic	Technique	Evidence
Credential Access	T1555 – Credentials from Password Stores	Web Browser Password Viewer execution
Execution	T1059.001 – PowerShell	PowerShell commands used to modify Microsoft Defender configuration
Execution	T1047 – Windows Management Instrumentation	WMIC commands interacting with MSFT_MpPreference
Defense Evasion	T1562.001 – Impair Defenses: Disable or Modify Tools	Registry and PowerShell activity targeting Microsoft Defender
Defense Evasion	T1070 – Indicator Removal	Suspicious processes terminated and associated binaries deleted
Command and Control	T1071* / Network Communication	Malicious outbound communication identified from IonicLarge.exe

Note: ATT&CK mappings should be treated as investigative classifications rather than definitive attribution. The exact technique for the network communication should be determined from the protocol and destination details available in the logs.

Impact Assessment

The endpoint should be considered potentially compromised based on the combination of malicious execution, credential-access activity, command-and-control communication, and attempts to weaken endpoint security.

Potential impacts include:

Credential exposure: The Web Browser Password Viewer may have accessed credentials stored within web browsers.
Loss of endpoint security: Microsoft Defender protections were modified, potentially allowing additional malicious activity to execute without detection.
Command-and-control communication: The malicious outbound connection indicates that the compromised endpoint may have communicated with attacker-controlled infrastructure.
Potential persistence or additional compromise: The presence of multiple suspicious binaries warrants additional investigation for persistence, lateral movement, and additional payloads.
Evidence destruction: Process termination and file deletion may have reduced available forensic evidence.

Because the affected user is a Financial Analyst, additional investigation should determine whether sensitive financial, corporate, or authentication information was accessible from the compromised endpoint.

Containment Recommendations

Based on the findings, the following actions would be appropriate for incident response:

Isolate the affected endpoint from the network to prevent additional command-and-control communication or lateral movement.
Preserve forensic evidence before performing extensive remediation, including relevant Windows Event Logs, Sysmon logs, memory, and disk artifacts where possible.
Reset potentially exposed credentials, particularly browser-stored credentials and credentials used from the affected endpoint.
Restore Microsoft Defender security configurations and verify that endpoint security protections are fully operational.
Block the identified malicious IP address and file hashes through applicable security controls.
Search the environment for the identified IOCs, including malicious hashes, filenames, IP addresses, registry modifications, and command-line activity.
Investigate for persistence and lateral movement, including scheduled tasks, services, startup locations, additional user accounts, and authentication events.
Perform a full endpoint security scan and forensic investigation to identify any remaining malware or evidence of compromise.
If the integrity of the system cannot be confidently restored, reimage the endpoint following organizational incident-response procedures.
Detection Opportunities

The investigation also identified several opportunities for improving defensive monitoring and detection capabilities.

Process Execution

Monitor Sysmon Event ID 1 for:

Executables launched from user Temp directories.
Randomly generated or suspicious executable names.
Credential recovery and password-viewing utilities.
Suspicious use of taskkill.exe.
PowerShell processes with unusual command-line arguments.
Microsoft Defender Modification

Monitor for:

Sysmon Event ID 13 registry modifications involving Windows Defender policy locations.
PowerShell or WMIC activity interacting with MSFT_MpPreference.
Attempts to modify or disable endpoint security protections.
Changes to Defender exclusions or threat-response settings.
Network Activity

Monitor for:

Outbound connections from suspicious processes.
Connections to known malicious IP addresses.
Temporary-directory executables establishing external network connections.
Unusual network activity originating from user workstations.
IOC-Based Detection

The following indicators could be added to threat-hunting and detection workflows:

MD5:
7165E9D7456520D1F1644AA26DA7C423

Malicious IP:
2[.]56[.]59[.]42

Suspicious binaries:
11111.exe
IonicLarge.exe
PalitExplorer.exe

Registry:
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

These indicators should be used in combination with behavioral detections rather than relied upon exclusively, as attackers can easily change filenames, hashes, and infrastructure.

Lessons Learned

This investigation demonstrated the importance of correlating multiple sources of endpoint telemetry rather than investigating individual events in isolation.

Several individual events could potentially appear benign when viewed separately. However, correlating process creation, registry modifications, network connections, and command-line activity revealed a much clearer picture of the attack.

Key takeaways include:

Sysmon provides valuable endpoint visibility for process execution, network connections, and registry activity.
Command-line analysis can reveal attacker behavior that may not be immediately apparent from process names alone.
Threat intelligence can help validate suspicious indicators, but reputation data should be correlated with internal telemetry before reaching a conclusion.
Defense evasion activity is an important indicator of compromise. Attempts to disable or modify security controls should receive immediate attention.
IOC correlation strengthens investigations. Connecting a suspicious process to a malicious IP address and security-control modifications provided stronger evidence of compromise than any single indicator alone.
Detection should focus on behavior as well as known IOCs, since attackers can change filenames, hashes, and infrastructure.
Incident documentation is an important SOC skill. Recording the investigation methodology, evidence, findings, and recommended actions makes the investigation reproducible and easier to communicate to other analysts or stakeholders.
Overall Assessment

The investigation identified a high-confidence endpoint compromise involving credential-access activity, malicious process execution, external command-and-control communication, modification of Microsoft Defender protections, and attempts to terminate processes and remove associated artifacts.

The combination of these behaviors indicates that the activity went beyond a single malicious file execution and warrants treating the endpoint as a security incident requiring containment, credential remediation, forensic investigation, and an environment-wide search for related indicators.




AI Assistance Disclosure

AI assistance was used during the documentation phase of this investigation. I independently performed the investigation, analyzed the Splunk logs, identified the indicators of compromise, and conducted the associated threat intelligence research.

AI was used only to help organize and consolidate my findings, improve the presentation of the investigation, and assist with developing the Lessons Learned and Containtment Recommended Actions sections.

The investigative findings, analysis, and conclusions presented in this write-up are based on my own work and understanding of the challenge.


