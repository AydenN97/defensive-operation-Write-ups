# Title: Challenge 4 Write-up Boogeyman 2


# Introduction


***Scenario Overview:*** The threat actor group from Boogeyman challenge 1 have returned with new tactics, techniques, and procedures(TTPs). Maxine, a human resource specialists open what she thought was an application from a recruit, but was actually malware that compromised her workstation. 

***Objective:*** Analyze the TTPs used by the threat actor group known as Boogeyman by performing forensic analysis on a copy of a phishing email and a memory dump file. 

**Environment:** Linux 

**Tools and Technologies Used:**
- Volatility
- Bash
- Olevba (tool used for extracting VBA macros from Microsoft Office Documents)
- Hashing 

**Notable Artifacts:**
- copy of phishing email ```Resume-Application for Junior IT Analyst Role.eml```
- Memory dump file ```WKSTN-2961.raw```


***Goals:***
- Analyze an potentially malicious attachment using Bash.
- Gain experience in using the forensic tool volatility.
- Demonstrate skill in using volatility to successfully identify TTPs of a threat actor group's attack chain.
- Shore up and enhance report writing.


# Start of Investigation 

### Task 1: The Email Analysis

Our first step within this task is to gather some basic information regarding the email. 
- The email sender: ```westaylor23@outlook.com```
- The email recipient: ```maxine.beck@quicklogisticsorg.onmicrosoft.com```
- The name of malicious attachment: ```Resume_WesleyTaylor.doc```

<img width="1590" height="564" alt="image" src="https://github.com/user-attachments/assets/2ded5f15-15b0-4973-819f-ec65cea2d751" />


Next we pivot towards analyzing the malicious document 
- We first look to get the md5 hash of the .doc using md5sum. The resulting hash is ```52c4384a0b9e248b95804352ebec6c5b```. We save this value, it will be handy for reporting and cyber threat intel. 
- Next we will use Olevba, a tool dedicated to performing analysis on .doc files (Microsoft MACROS). The tool gives us a nice table detailing specific Indicators of Compromise(IOCs) and suspicious functions found in the macro.

<img width="728" height="468" alt="image" src="https://github.com/user-attachments/assets/4134d383-b4ce-4443-8603-bf4f5a77e9ca" />

- Most noteworthy of the IOCs is an URL ```hxxps[://]files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]png``` that may be responsible for the downloading of a malicious payload.
- Analyzing the code of the Macro, we can actually see the initial retrieval of the file from the suspicious URL as well as the executable ```wscript.exe``` which executes the downloaded payload, a javascript file named ```update.js```. See the image below

<img width="976" height="340" alt="image" src="https://github.com/user-attachments/assets/b1ca1afe-0048-4518-bd9b-aa7989e62b12" />

- The full path of the payload is ```C:\ProgramData\update.js```


  
