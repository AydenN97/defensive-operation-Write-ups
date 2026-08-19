# Title: Challenge 5 Write-up: Boogeyman 3

# Introduction



***Scenario Overview:*** The Threat actor group known as Boogeyman as returned for a third time. They still continue with their trademark technique of phishing(T1566) to achieve initial access. We must investigate the compromise following the phishing email to see if the group as evolve or employed new tactics and techniques.  


***Additional Details:***
- The phishing email, a tactic commonly used by the Boogeyman threat actor, was sent to CEO Evan Hutchinson, who subsequently informed the security team that he had clicked on the attachment.
- This activity is indicative of spearphishing, specifically because the threat actor targeted a high-ranking individual. In previous Boogeyman activity, the threat actor primarily targeted regular employees rather than  senior leadership.
- The security investigated the CEO's workstation where they discovered an ISO payload inside the suspected malicious attachment, which was found in the downloads folder of the CEO.
- The security team determined that the incident likely occurred between August 29 and August 30, 2023, establishing the approximate timeframe for the investigation.


***Objective:*** Analyze and Assess the impact of the compromise of the CEO's Workstation and determine if the threat actor was able to compromised other machines within the network.

***Environment:*** Analysis will be conducted via a Linux machine. 

***Tools and Technologies Used:***
- Sysmon
- Elastic Stack: Kibana


***Learning Goals:***
- Leverage Sysmon and Kibana from the Elastic Stack for centralized log viewing.
- Gain familiarity with Kibana Query Language (KQL).
- Recognize when and what Sysmon event codes are needed for hunting for a particular artifact.
- Improve report writing skills.


# Start of Investigation 

**Task 1:** Enter Kibana through our Elastic Stack environment to access the necessary logs and establish the investigation scope.
- Before beginning the investigation, we must first set the appropriate time range. The security team identified the relevant timeframe as ```August 29, 2023, through August 30, 2023.```


<img width="441" height="63" alt="image" src="https://github.com/user-attachments/assets/5705d104-3ad1-4593-bd1a-0bdd0931f73f" />



**Task 2:** Find the process that executed the initial stage 1 payload.
- We know that our victim, CEO Evan Hutchinson,  had clicked on the likely malicious attachment when he received the email. The security team, upon investigating the workstation of the victim, discovered the attachment in the Downloads folder of the victim's account. The attachment is supposedly a pdf file named ```ProjectFinancialSummary_Q3.pdf```. Hutchinson had reported to the security team that the email appeared suspicious.
- With these facts in mind, my initial step will be simply to search for all log events including this file and process execution. Kibana Query ```_index:winlogbeat-* and ProjectFinancialSummary_Q3.pdf and event.code:"1"```.
- Luckily they are only 4 hits, limiting the noise greatly. 
- In the first of the 4 log events, we see that commonly named LOL Binary ```MSHTA.EXE``` is used to execute the suspicious file, which interestingly we learned is a double file extension. ```ProjectFinancialSummary_Q3.pdf.hta```.
- Double file extensions are a common tactic used by threat actors to hide a dangerous program and trick users into opening it. 
- The process ID for this event is **6392**.

<img width="1250" height="149" alt="image" src="https://github.com/user-attachments/assets/7faeadd4-80f2-4356-8227-8641c553413d" />

**Task 3:** The stage 1 payloads implants a file to another location, find it. 
- The very next log entry, we now analyze ```ProjectFinancialSummary_Q3.pdf.hta``` as the parent process for which it launches a process by named of ```xcopy.exe```.
- ```xcopy.exe``` runs the following command ```C:\Windows\System32\xcopy.exe, /s, /i, /e, /h, D:\review.dat, C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat```.
- This command implants a file to Hutchinson's temp folder, a common location for malware to hide and remain persistent.

<img width="1125" height="247" alt="image" src="https://github.com/user-attachments/assets/b30b1be6-992e-4574-a563-865d60d3673f" />


**Task 4:** The implanted file was eventually used and executed by the stage 1 payload. Find What is the full command-line value of this execution.
- Same process as task 2, we follow the chain of logs and see that our parent process, reminder that this is ```ProjectFinancialSummary_Q3.pdf.hta``` and ```parent.process.id: 6392``` has launched rundll32.exe
- rundll32.exe ran the following command ```"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer```.
- We see the ```review.dat``` file created in task 3 being executed.


**Task 5:** The stage 1 payload established a persistence mechanism. Find the name of the scheduled task created by the malicious script
- The file ```review.dat``` was created as a scheduled task, evident by the screenshot below.

<img width="1199" height="63" alt="image" src="https://github.com/user-attachments/assets/cece8ae5-a40c-4232-95eb-b3d4936e98bb" />

**Task 6:** The execution of the implanted file inside the machine has initiated a potential C2 connection. Find the IP and port used by this connection.
- We start by narrowing our search down to any events involving our ```review.dat```.
- Luckily, there are only 12 hits, so using other filters will be unnecessary.
- looking through the results I did not see any evidence of C2 connection, but I did notice powershell.exe usage.
- I decided to narrow down the search results based on event.code 3 as well as Powershell.exe.
- Kibana Query: ```_index:winlogbeat-* and process.name: "powershell.exe" and event.code: "3"```.
- Analyzing the results, there were over 6500 events related to an destination IP address of ```165[.]232[.]170[.]151``` and port ``80``.

<img width="505" height="497" alt="image" src="https://github.com/user-attachments/assets/73c8eaac-7aaf-4973-a95f-803635a2b675" />


**Task 7:** The attacker has discovered that the current access is a local administrator. Find the name of the process used by the attacker to execute a UAC bypass.
- While working through task 5, I had observed ```review.dat``` enumerating the administrators group using ```net.exe```.
- The very next log entry included the execution of a file named ```fodhelper.exe```.
- researching ways attackers can accomplish a UAC bypass, the fodhelper executable came up as a common technique.

<img width="519" height="219" alt="image" src="https://github.com/user-attachments/assets/dc28a7ae-ad13-4da2-8125-c2c283ee0d3c" />
<img width="1239" height="139" alt="image" src="https://github.com/user-attachments/assets/f95167da-21af-4c4e-bf32-0560996a1ed0" />

**Task 8:** Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. Find the GitHub link used by the attacker to download a tool for credential dumping
- We search for any instance of GitHub within the logs.
- We find that the threat actor used Powershell.exe to download mimikatz from GitHub.
- Full link: ```https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip```.
- The Mimikatz tools was saved under ```mimi.zip```.

  <img width="1569" height="561" alt="image" src="https://github.com/user-attachments/assets/b6e8ba3e-7f02-4abd-9f24-34861ef52127" />


**Task 9:** After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. Find the username and hash of the new credential pair.
- We search for all logs with the instance of ```Mimikatz.exe```.
- Searching the results, I find the user account ```itadmin``` and its ntlm hash ```F84769D250EB95EB2D7D8B4A1C5613F2```. 

<img width="1003" height="256" alt="image" src="https://github.com/user-attachments/assets/0b813204-c744-4b20-8cb4-e8ada7523648" />


**Task 10:** 
