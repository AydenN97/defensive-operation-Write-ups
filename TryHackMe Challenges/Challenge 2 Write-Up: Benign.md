***Title:*** Challenge 2 Write-Up: Benign 

***Scenario Overview:*** A client's Intrusion Detection System(IDS) indicated a potentially suspicious process execution on one the hosts from the HR department. The possibility of a compromised workstation within the HR department warrants an investigation. 

***Background:*** We are provided with the windows event logs belonging to the potentially compromised workstation. From the windows event logs, unfortunately only the process execution logs with Event ID:4688 are ingested into the index: **win_eventlogs.**

***Objective:*** Identify and investigate the infected host by anwsering the guided questions.

***Goals:***
- Gain and demonstrate practical experience using Splunk Search as a Security Information and Event Management (SIEM) platform.
- Strengthen threat detection and event correlation skills by analyzing security logs and identifying suspicious activity.
- Develop and strengthen SOC investigation and incident analysis skills.
- Improve technical report-writing skills by documenting investigation findings, evidence, and recommended actions.


**Categories:** Blue Team / SIEM / Endpoint Investigation. 

**Environment and Tools Used:** Linux / Splunk Search.


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

