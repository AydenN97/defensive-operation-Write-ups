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


**Tools/Technologies Used:**
- KAPE
- Windows Command Prompt
- Windows Event Viewer
- Eric Zimmerman(EZ) tool suite
- MFTExplorer (EZ Tools)
  

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
- 

*$MFT Log Analysis:*
- Included in our artifacts is an $MFT log, which we can parse using Eric Zimmerman MFTE Explorer.
- After the $MFT file loads, it is best to start looking for suspicious executables and files in suspicious/unusual locations.
- 


***ON GOING*** ***INVESTIGATION STILL IN PROGRESS***
  
