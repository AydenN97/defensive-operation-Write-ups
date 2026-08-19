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

