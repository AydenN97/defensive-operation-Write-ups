***Title:*** Challenge 6 Write-up: The Vantara Leak


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

**Categories:** Blue Team / Digital Forensics / Compromised Endpoint Investigation

**Environment:** Windows 11 Forensics Workstation - Virtual Machine

**Note*: Report Audience: The report is written for a technical audience, including fellow cybersecurity enthusiasts, students, and professionals. Therefore, basic technical concepts and commonly understood security tools and utilities will not be explained in detail. For example, the functions and common uses of certutil.exe are assumed to be understood by the intended audience.

**Tools/Technologies Used:**
- KAPE
- Windows Command Prompt
- Windows Event Viewer
- Timeline Explorer
- Eric Zimmerman(EZ) tool suite
- MFTExplorer (EZ Tools)
- LogParser (EZ Tools)
  

**Goals as a Cybersecurity Student:**
- Improve my digital forensics and investigative skills, particularly when analyzing evidence and identifying potential indicators of compromise.
- Become more effective at finding and leveraging available resources when I am stuck, while developing the ability to work through problems without immediately knowing the solution.
- Gain familiarity and hands-on experience with common digital forensics tools and techniques.
- Improve my technical report-writing skills.

# Start of Investigation 


**Background:** 
Prior to starting the investigation, our lead tells us that our forensic workstation contains KAPE artifacts located here: C:\Users\DFIRUser\Vantara-Artefacts.zip. The artifacts contained in the ZIP file were all pulled from the compromised file server. The following artifacts are included:
- Windows Console Log.csv
- Windows SkipLog.csv
- Windows CopyLog.csv
- Program Data (file folder)
- Users (file folder)
- Windows (file folder)
- $Boot
- $J 
- $LogFile
- $MFT
- $Secure_$SDS
- Full Winevt system, security, and Application logs


***Task 1: Find how the attacker gained Initial Access and any tools that were used.***

We are given access to the three major log sources that come with Windows systems: System, Security, and Application. The Security log, in particular, is where I start my investigation, looking for anomalous events relating to process creation, scheduled task creation, successful/failed logons, user account modification/creation, and service installation. Our lead, Daniel informs us that there is also a contractor with legitimate access to that system, so we should not assume everything unusual is the attacker. Daniel informs us that an executable was launched interactively from the Downloads folder on the incident date (June 5).

*Windows Security Log Findings:* 
- Process Creation logs revealed the presence of several legitimate system processes. Further investigation would be required to determine whether any of these processes were being abused for malicious purposes. We also have access to the process command line log which should reveal more. 
- No schedule task creation or service creation
- No unusual logins or account modifications

*Windows System Log:*
- Within the security log, important events to keep an out for mainly relate to changes to core system components, such as the OS, certain services, and drivers. Overall, things to look out for include: Error/critical events, Disk/file system events, Driver Activity, and task scheduler.
- I will conduct my analysis using various event ID's and detail any interesting finds, of course anything of note will always have to be correlated with other artifacts from other logs, or applications such as PowerShell.

*Windows System Log Findings:*
- Nothing overtly malicious or suspicious was identified within the logs. The majority of the events were related to system time synchronization.
  

*$MFT Log Analysis:*
- Included in our artifacts is an $MFT log, which we can parse using Eric Zimmerman MFTE Explorer. According to online research, The Master File Table ($MFT) is a core NTFS filesystem database that contains a record for essentially every file and directory on an NTFS volume. When parsed, we will have the ability to explore the entire filesystem on the volume extracted from the compromised host.
- After the $MFT file loads, it is best to start looking for suspicious executables and files in suspicious/unusual locations.
- Unfortunately, MFTExplorer would not load the file, so we will have to use MFTCmd instead. command ```MFTECmd.exe -f $MFT --csv C:\Users\DFIRUser\Desktop\Evidence\MFT_Output```.
- We will use timeline explorer to parse the newly created csv.

*MFT Log Findings:*
- If we remember earlier, our lead informed us earlier that an executable was launched from the downloads folder on the incident data. I narrow down the directory to ```C\Users\daniel.avery\Downloads``` where I found the following executable: ```VPNsetup_v2.1.exe```. Other executables and files are within the directory are seen in the image below. Could the execution of this file be our initial access method? 

<img width="1570" height="238" alt="image" src="https://github.com/user-attachments/assets/76dd5b0a-758b-47dd-877e-a76769544038" />

- We see the creation date of 2026-06-05.
- Next step will be to get the hash of this executable. Unfortunately the ```VPNSetup_v2.1.exe``` executable itself was not present within the available forensic artifacts, preventing calculation of a cryptographic hash. Further investigation would be required to get a possible hash.

- While analyzing the file system of the daniel.avery user, I came across consolehost_history.txt file which contained commands. The screenshot below details the commands.

<img width="545" height="163" alt="image" src="https://github.com/user-attachments/assets/046db676-c418-42db-ae19-8de252169a20" />

- Looking for files in unusual locations, I stumbled across the ```svchost``` executable located in the temp folder of our user ```daniel.avery``` which is highly unusual since svchosts.exe typically lives in C:\Windows\System32. 
  
<img width="1365" height="91" alt="image" src="https://github.com/user-attachments/assets/8a0b4d58-8367-4196-a354-ec85874b0abb" />

**$LogFile and $J Analysis:**
- I will use LogParser to parse this log into a CSV file, which can then be loaded into Timeline Explorer for further analysis.
- I am looking for evidence of the creation of svchost.exe in the Temp folder, along with any other notable findings.
- A significant finding is SVCHOSTS.exe, which was confirmed to be present in the Temp folder. I initially overlooked this file, but its presence is suspicious because it is likely an impersonation attempt of the legitimate Windows binary, svchost.exe. The additional "s" at the end of the filename is consistent with a form of typosquatting that could be used to make the malicious executable appear legitimate.
- Examining the Prefetch folder, which can provide evidence that a program was executed on the system, we again see evidence of the fake svchosts.exe file. This strengthens the conclusion that the suspicious executable was not only present on the system but was also executed.
- I initially thought that SVCHOST.exe was legitimately put in the temp folder and that the placement was suspicious, however I missed that the file I was looking at was actually SVCHOST(S), which is not normal spelling for the native windows binary.

<img width="180" height="325" alt="image" src="https://github.com/user-attachments/assets/eda3630e-a67f-48cf-86f3-28dd9259c5e0" />

**Prefetch analysis:**
- Interestingly, immediately before the suspicious SVCHOSTS.exe file was executed, the legitimate Windows utility certutil.exe was also executed. Given the timing and the role of certutil.exe, this is a significant finding.
- This suggests that ```certutil.exe``` may have been used by the attacker to download or otherwise deliver the suspicious ```SVCHOSTS.exe``` file to the system. The close time relationship between the two executions supports this as a possible delivery mechanism, although additional evidence would be needed to confirm the exact method used.

<img width="372" height="46" alt="image" src="https://github.com/user-attachments/assets/d91a71f1-5aee-469f-be6f-0cf85dd91064" />



   




  

***INVESTIGATION STILL IN PROGRESS***
  
