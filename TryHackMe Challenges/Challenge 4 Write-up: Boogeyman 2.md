# Title: Challenge 4 Write-up Boogeyman 2


# Introduction


***Scenario Overview:*** The threat actor group from Boogeyman challenge 1 have returned with new tactics, techniques, and procedures(TTPs). Maxine, a human resource specialists open what she thought was an application from a recruit, but was actually malware that compromised her workstation. 

***Objective:*** Analyze the TTPs used by the threat actor group known as Boogeyman by performing forensic analysis on a copy of a phishing email and a memory dump file. 

***Environment:*** Linux 

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

## Task 2: Memory Dump Analysis

We now pivot to analyzing the memory dump with Volatility in Task 2, which will also be our final task. We have collected all the evidence we can from the email and the malicious attachment. We now will analyze the memory dump of the workstation to get a grasp of what the downloaded payload did, mainly looking for behaviors consistent with further down the kill chain stages such as persistence, collection, and exfiltration.  

A good first step is to get the PID of the process that executed the payload.
- I believe this command ```vol -f WKSTN-2961.raw windows.pslist.PsList``` should give us a full process list to be able to locate the PID of the process that executed the stage 2 payload
- (If I remember correctly, the executable responsible for launching the payload was ```wscript.exe```)
- We locate wscript.exe and get a PID of **4260** and a PPID of **1124**

<img width="495" height="61" alt="image" src="https://github.com/user-attachments/assets/1e0957da-7a2e-4d1d-8ef1-19c603b762a8" />

The final thing I do is run a few Volatility plugins that would be useful for this investigation, such as malfind, cmdline, netscan, filescan, etc., to see what IOCs I can find.
Final results gathered: 
- Executables already discovered such as ```Wscript.exe``` and ```update.js```.
- Looking back at the PsList scan results, I did see two processes of note ```updater.exe and DumpIT.exe```.
- When running the cmdline plugin, I did find the path for which updater.exe was executed ```C:\Windows\Tasks\updater.exe``` as well as the path of the malicious email. ```C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc```.
- When running the netscan plugin, I found the IP address and Port that updater.exe establishes, presumably the C2 server connection ```128[.]199[.]95[.]189:8080```.
- One final task by our supervisor is to find the scheduled task created by the attacker. This took me some research as the previous plugins that I had used led me nowhere. I had an inclimination that I needed to grep for schtasks, but I did not know how to form the command. With some research I found this command ```strings vol -f WKSTIN-2961.raw | grep -i schtasks``` to work. I had been missing the strings at the beginning of the command.
- The resulting schedule task was found ```schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'```. 

<img width="1210" height="37" alt="image" src="https://github.com/user-attachments/assets/ccb36bb7-8678-4d59-827f-f5430a12d279" />

<img width="1578" height="309" alt="image" src="https://github.com/user-attachments/assets/0f77d44d-8c0d-4854-9df3-6b4dd076cd0d" />

<img width="1578" height="571" alt="image" src="https://github.com/user-attachments/assets/07868d1c-4569-48bb-9f84-d593dceaac51" />

## Conclusion

This investigation demonstrated how the Boogeyman threat actor group used a phishing email and malicious Microsoft Word document to compromise Maxine's workstation and establish further access. By analyzing the email and its attachment, I identified the malicious document, calculated its MD5 hash, and used Olevba to uncover suspicious VBA macros. The macro analysis revealed a connection to a malicious URL that downloaded update.js, which was subsequently executed using wscript.exe.

Memory analysis with Volatility provided additional insight into the attack chain. I identified the wscript.exe process responsible for executing the payload, as well as additional suspicious processes including updater.exe and DumpIT.exe. The investigation also uncovered the execution path of updater.exe, the location of the malicious Word document, and a network connection from updater.exe to the suspected C2 server at 128[.]199[.]95[.]189:8080.

Finally, I identified a scheduled task named Updater that was created to execute a hidden PowerShell command. The command retrieved and decoded data stored in the Windows Registry before executing it, demonstrating the attacker's use of scheduled tasks, PowerShell, Base64 encoding, and registry-based storage to maintain persistence and execute malicious code.

Overall, this investigation provided a clear view of the Boogeyman group's attack chain, from the initial phishing email and malicious attachment to payload execution, C2 communication, and persistence. The investigation also reinforced the importance of combining email analysis, malware analysis, memory forensics, and command-line tools when investigating a compromised Windows system. These techniques allowed me to identify multiple indicators of compromise and better understand the TTPs used throughout the attack.







