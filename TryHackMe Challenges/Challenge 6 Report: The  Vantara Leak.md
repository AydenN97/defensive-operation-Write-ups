***Title:*** Challenge 6 Report: The Vantara Leak


***Scenario Overview/Objective:*** I have been tasked, as a digital forensic analyst for TSS, to perform a forensics investigation on a compromised workstation. The client is Vantara Financial Group which operates within the financial services industry. On June 5th, Vantara Financial Group's SOC detected anomalous authentication against a finance-department file server. Large outbound traffic to an unknown host quickly followed. The file server was isolated by Vantara Financial Group's Incident Response team. Vantara can not attest to the full scope of the breach, such as how long the attacker had access, and if any other systems were breached as well. TSS has been tasked to scope the breach, determining the impact and erasing the adversaries access to the machine fully. 



***Mission Parameters:***
- Establish how the attacker gained initial access and what tools were used.
- Determine how persistence was maintained on the compromised machine.
- Assess whether the attacker attempted to move beyond the initial point of compromise.
- Identify any unauthorized accounts or activity not attributed to legitimate users.
- Confirm whether sensitive data was accessed or staged and quantify the exposure.


# Room Information

**Difficulty:** 🟡 Medium

**Room Link:** [https://tryhackme.com/room/thevantaraleak]

**Categories:** Blue Team / Digital Forensics / Endpoint Investigation

**Environment:** Windows 11 Forensics Workstation

**Note*: Report Audience: The report is written for a technical audience, including fellow cybersecurity enthusiasts, students, and professionals. Therefore, basic technical concepts and commonly understood security tools and utilities will not be explained in detail. For example, the functions and common uses of certutil.exe are assumed to be understood by the intended audience.

**Tools/Technologies Used:**
- Windows Command Prompt
- Windows Event Viewer
- Timeline Explorer
- Eric Zimmerman(EZ) tool suite
- MFTExplorer (EZ Tools)
- LogParser (EZ Tools)
- AmCacheParser (EZ Tools)
- Registry Explorer
  

**Goals as a Cybersecurity Student:**
- Improve my digital forensics and investigative skills, particularly when analyzing evidence and identifying potential indicators of compromise.
- Become more effective at finding and leveraging available resources when I am stuck, while developing the ability to work through problems without immediately knowing the solution.
- Gain familiarity and hands-on experience with common digital forensics tools and techniques.
- Improve my technical report-writing skills.

# Start of Investigation 


**Background:** 
Prior to starting the investigation, our lead tells us that our forensic workstation contains artifacts located here: ```C:\Users\DFIRUser\Vantara-Artefacts.zip```. The artifacts contained in the file were collected as evidence from the compromised file server. The following artifacts include:
- Windows Console Log.csv
- Windows SkipLog.csv
- Windows CopyLog.csv
- Program Data (file folder)
- Users (file folder)
- Windows (file folder)
- amcache.hve
- $Boot
- $J 
- $LogFile
- $MFT
- $Secure_$SDS
- Winevt system, security, and Application logs
- Other Winevt logs: Task scheduler 


***Task 1: Finding how the attacker gained Initial Access and any tools that were used.***

We are given access to the three major log sources that come with Windows systems: System, Security, and Application. The Security log, in particular, is where I start my investigation, looking for anomalous events relating to process creation, scheduled task creation, successful/failed logons, user account modification/creation, and service installation. Our lead, Daniel informs us that there is also a contractor with legitimate access to that system, so we should not assume everything unusual is the attacker. Daniel informs us that an executable was launched interactively from the Downloads folder on the incident date (June 5).

**Windows Security Log Findings:** 
- Process Creation logs revealed the presence of several legitimate system processes. Further investigation would be required to determine whether any of these processes were being abused for malicious purposes. We also have access to the command line logging history which should reveal more. 
- No schedule task creation or service creation.
- No unusual logins.
- A user account was created: helpdesk$ by user daniel.avery.

**Windows System Log:**
- Within the security log, important events to keep an eye out for are mainly related to changes to core system components, such as the OS, certain services, and drivers. Overall, things to look out for include: Error/critical events, Disk/file system events, Driver Activity, and task scheduler.
- I will conduct my analysis using various event ID's, detailing anything that may be suspicious.

**Windows System Log Findings:**
- Nothing overtly malicious or suspicious was identified within the logs. The majority of the events were related to system time synchronization.
  

**$MFT Log Analysis:**
- Included in our artifacts is an $MFT log, which we can parse using Eric Zimmerman MFTE Explorer. Researching the log, The Master File Table ($MFT) is a core NTFS filesystem database that contains a record for essentially every file and directory on an NTFS volume. When parsed, we will have the ability to explore the entire filesystem on the volume extracted from the compromised host.
- After the $MFT file loads, it is best to start looking for suspicious executables and files in suspicious/unusual locations.
- Unfortunately, MFTExplorer would not load the file, so we will have to use MFTCmd instead,  which is the command line utility for MFTExplorer. command ```MFTECmd.exe -f $MFT --csv C:\Users\DFIRUser\Desktop\Evidence\MFT_Output```.
- We can then use timeline explorer to examine the newly created csv.

**MFT Log Findings:**
- If we remember earlier, our lead informed us earlier that an executable was launched from the downloads folder on the incident data. I narrow down the directory to ```C\Users\daniel.avery\Downloads``` where I found the following executable: ```VPNsetup_v2.1.exe```. Other executables and files are within the directory are seen in the image below. Could the execution of this file be our initial access method? 

<img width="1570" height="238" alt="image" src="https://github.com/user-attachments/assets/76dd5b0a-758b-47dd-877e-a76769544038" />

- We see the creation date of 2026-06-05, the date which we were informed was likely the start of the incident. 
- Next step will be to get the hash of this executable. Unfortunately the ```VPNSetup_v2.1.exe``` executable itself was not present within the parsed MFT log. Further investigation would be required to get a hash.
- Based on the available artifacts, I determined that the Amcache hive may contain the hash of VPNSetup_v2.1.exe, as the Amcache commonly contains information about executable files encountered by the Windows operating system. We will parse the Amcache hive using Eric Zimmerman's AmcacheParser to determine whether a hash for VPNSetup_v2.1.exe is present.
- The resulting hash is found: ```SHA1d3c83599d21508c14ffe67d87abf5a83ddc4d157```

<img width="998" height="40" alt="image" src="https://github.com/user-attachments/assets/75b1885c-41c8-4253-8283-e3415f0eeca2" />


- While analyzing the file system of the daniel.avery user, I came across consolehost_history.txt file which contained commands. The screenshot below details the commands.

<img width="545" height="163" alt="image" src="https://github.com/user-attachments/assets/046db676-c418-42db-ae19-8de252169a20" />

- Looking for files in unusual locations, I stumbled across the ```svchosts``` executable located in the temp folder of our user ```daniel.avery``` which is highly unusual since svchosts.exe typically lives in C:\Windows\System32. 
  
<img width="1365" height="91" alt="image" src="https://github.com/user-attachments/assets/8a0b4d58-8367-4196-a354-ec85874b0abb" />

**$LogFile and $J Analysis:**
- I will use LogParser to parse this log into a CSV file, which can then be loaded into Timeline Explorer for further analysis.
- I am looking for evidence of the creation of svchost.exe in the Temp folder, along with any other notable findings.
- A significant finding is ```SVCHOSTS.exe```, which was confirmed to be present in the Temp folder. I initially overlooked this minor detail; however, its presence is suspicious because it may represent an impersonation attempt of the legitimate Windows binary, svchost.exe. The additional “s” at the end of the filename is consistent with a form of typosquatting that could be used to make a malicious executable appear legitimate.
- Examining the Prefetch folder, which can provide evidence that a program was executed on the system, we again see evidence of the fake svchosts.exe file. This strengthens the conclusion that the suspicious executable was not only present on the system but was also executed.
- I initially thought that the legitimate ```SVCHOST.exe``` was  put in the temp folder and that just the placement was suspicious, however I missed that the file I was looking at was actually SVCHOST(S), which is a completly different binary/file and not normal spelling for the native windows binary.

<img width="180" height="325" alt="image" src="https://github.com/user-attachments/assets/eda3630e-a67f-48cf-86f3-28dd9259c5e0" />

**Prefetch analysis:**
- Interestingly, immediately before the suspicious SVCHOSTS.exe file was executed, the legitimate Windows utility certutil.exe was also executed. Given the timing and the role of certutil.exe, this is a significant finding.
- This suggests that ```certutil.exe``` may have been used by the attacker to download or otherwise deliver the suspicious ```SVCHOSTS.exe``` file to the system. The close time relationship between the two executions supports this as a possible delivery mechanism, although additional evidence would be needed to confirm the exact method used.

<img width="372" height="46" alt="image" src="https://github.com/user-attachments/assets/d91a71f1-5aee-469f-be6f-0cf85dd91064" />


***Task 1 Summary — Initial Access and Tools:***

The investigation identified several artifacts associated with the compromise, although the exact initial access vector could not be conclusively determined from the available evidence.

The Windows Security and System logs did not reveal any obvious malicious logons, account modifications, scheduled task creation, service installation, or other overtly suspicious activity. However, analysis of filesystem artifacts provided more significant findings. The $MFT revealed an executable named VPNSetup_v2.1.exe in C:\Users\daniel.avery\Downloads, with a creation date matching the incident date of June 5. This is notable because the incident lead specifically reported that an executable was launched interactively from the Downloads folder on that date. The executable itself was not present in the forensic artifacts, preventing further analysis or hash calculation.

Additional filesystem analysis identified SVCHOSTS.exe in the user's Temp directory. The filename is highly suspicious because it closely resembles the legitimate Windows svchost.exe binary while adding an additional "s". Prefetch artifacts provide evidence that SVCHOSTS.exe was executed on the system.

Prefetch analysis also showed certutil.exe executing immediately before SVCHOSTS.exe. Given certutil.exe's capabilities, it is possible that the utility was used to retrieve or deliver the suspicious executable. The temporal relationship between the two executions makes this a significant lead, but the available evidence is insufficient to definitively establish certutil.exe as the delivery mechanism.

Based on the current evidence, VPNSetup_v2.1.exe represents a potential initial-access vector, while certutil.exe and the impersonating SVCHOSTS.exe appear to be associated with subsequent stages of the activity. Further analysis of command-line artifacts, file contents, network artifacts, and additional forensic evidence would be necessary to establish the complete attack chain with confidence.



***Task 2: Finding ways the attacker may have maintained persistence.***

Now that we know a significant portion of the attacker's initial compromise occurred between 5:50 and 6:10 AM on June 5, with the execution of our suspicious VPNSetup_v2.1.exe occurring at approximately 6:01 AM, I wanted to briefly revisit the Windows Event Logs and scope my analysis to this timeframe.

I reviewed the Application, System, and Security logs for events occurring between 5:50 and 6:10 AM but did not identify anything of significance. I then remembered that one of the provided forensic artifacts was a Task Scheduler log, so I decided to review it for additional evidence of activity during this timeframe.

**Task Scheduler Log Findings:**
- Exactly at 6:01 AM, an scheduled task was registered by user daniel.avery: ```MicrosoftEdgeUpdateCore```.
- The full executable path is ```C:\Users\daniel.avery\AppData\Local\Temp\svchosts.exe```.


***Task 3: Assessing weather the attacker attempts to move beyond the initial point of compromise.***

This is where the ```consolehost_history.txt``` file extracted in task 1 comes in handy. The attack appeared to perform the following actions based off the console history:
| Command                                                  | Likely purpose                                                                                |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `whoami /all`                                            | Identifies the current user, groups, privileges, and security token                           |
| `net user /domain`                                       | Enumerates domain user accounts                                                               |
| `net localgroup administrators`                          | Identifies members of the local Administrators group                                          |
| `ipconfig /all`                                          | Collects network configuration, DNS, gateways, adapters, etc.                                 |
| `nltest /domain_trusts`                                  | Enumerates domain trusts and potentially identifies other domains                             |
| `net use Z: \\VFG-FS01\Finance /user:VFG\svc.backup ...` | Authenticates to a remote file share using the `svc.backup` account and maps it as drive `Z:` |

These actions are often synonymous with post-compromise reconnaissance and lateral movement.


***Task 4: Identifying any unauthorized accounts or activity not attributed to legitimate users.***

We know from the previous task that the attacker under the compromised account of daniel.avery was able to authenticate and gain access as the domain account: ```svc.backup```.
While parsing the SAM Registry hive of the compromised host, I came across a user account named ```helpdesk$```. The account was created by the compromised daniel.avery account.

<img width="700" height="125" alt="image" src="https://github.com/user-attachments/assets/2baa56bf-f7b2-4c8c-8b95-aa974a1e5f4d" />


***Task 5: Confirming whether sensitive data was accessed or staged and quantify the exposure.***
- The Windows Recent Items artifacts indicate that the user account ```daniel.avery``` interacted with the following sensitive files: ```Finance Reports```, ```Q1_Revenue```, ```week1_Notes```, ```Infrastructure Overview```, and ```Q1_2026_Revenue_Summary```.
- The files present in the user's Recent Items/Recent path do not directly indicate whether the files were created, accessed, or modified. However, the reconstructed $J file provides this information. I correlated the findings from the Recent Items path with the entries in the $J file and determined that all of these files were accessed after the initial compromise.

- A compressed archive named ```data_backup.zip``` was found in the temp folder. This was created shortly after initial compromise.

<img width="1565" height="35" alt="image" src="https://github.com/user-attachments/assets/b822d0e3-90fd-435e-80cd-b025d6ec9311" />



<img width="951" height="317" alt="image" src="https://github.com/user-attachments/assets/3f4aa229-2254-4288-984a-93b0b0cc5236" />


# Executive Summary

TSS conducted a digital forensic investigation of a compromised Windows 11 workstation belonging to Vantara Financial Group following the detection of anomalous activity against a finance-department file server and large outbound network traffic. The investigation focused on identifying the likely initial access vector, determining how the attacker maintained access, assessing potential lateral movement, identifying unauthorized activity, and determining whether sensitive data was accessed or staged.

The investigation identified multiple artifacts consistent with post-compromise activity. An executable named VPNSetup_v2.1.exe was identified in C:\Users\daniel.avery\Downloads with a creation timestamp matching the incident date of June 5. This finding is significant because the investigation lead reported that an executable had been interactively launched from the Downloads directory around the same timeframe. The Amcache hive also contained a SHA-1 hash associated with the executable. Although the available evidence suggests VPNSetup_v2.1.exe may have been involved in the initial compromise, the exact initial access vector could not be conclusively established.

Additional analysis identified SVCHOSTS.exe in the user's Temp directory. The filename closely resembles the legitimate Windows svchost.exe binary but contains an additional "s," making it suspicious and potentially indicative of an impersonation or typosquatting technique. Prefetch artifacts confirmed that the executable was executed. Furthermore, certutil.exe executed immediately before SVCHOSTS.exe, raising the possibility that certutil was used to retrieve or deliver the suspicious executable.

Evidence of persistence was also identified. At approximately 6:01 AM on June 5, a scheduled task named MicrosoftEdgeUpdateCore was registered by daniel.avery. The task was configured to execute C:\Users\daniel.avery\AppData\Local\Temp\svchosts.exe. The timing and executable path strongly associate the scheduled task with the suspicious executable identified during the investigation.

Command-line history revealed several reconnaissance activities consistent with post-compromise behavior. These included enumeration of the current user's privileges, domain accounts, local administrators, network configuration, and domain trusts. The attacker also used the svc.backup domain account to authenticate to the VFG-FS01\Finance network share. These activities indicate that the compromise extended beyond execution of a single suspicious file and included efforts to understand the environment and access additional resources.

The investigation also identified an account named helpdesk$, which was created by the compromised daniel.avery account. The creation of this account is suspicious and may represent an attempt to establish an additional means of access, although the available evidence does not independently establish the attacker's intent.

Finally, evidence indicates that sensitive financial and infrastructure-related files were accessed following the initial compromise. Recent Items artifacts identified interaction with Finance Reports, Q1_Revenue, week1_Notes, Infrastructure Overview, and Q1_2026_Revenue_Summary. Correlation with the reconstructed $J file confirmed that these files were accessed after the initial compromise. A compressed archive named data_backup.zip was also identified in the Temp directory and was created shortly after the compromise, providing evidence consistent with potential data staging.

Overall, the investigation identified evidence of initial compromise, execution of a suspicious impersonating executable, persistence through a scheduled task, post-compromise reconnaissance, access to a privileged/domain account and finance network share, creation of a potentially unauthorized account, and interaction with sensitive data. While the evidence strongly indicates malicious post-compromise activity, the exact initial access mechanism and the full extent of data exfiltration could not be conclusively determined from the available artifacts. Further analysis of network evidence, the original executables, command-line artifacts, and additional endpoint or server telemetry would be required to fully reconstruct the attack chain and quantify the extent of potential data exfiltration.


