# Title: Challenge 4 Write-up Boogeyman 2


# Introduction


***Scenario Overview:*** The threat actor group from Boogeyman challenge 1 have returned with new tactics, techniques, and procedures(TTPs). Maxine, a human resource specialists open what she thought was an application from a recruit, but was actually malware that compromised her workstation. 

***Objective:*** Analyze the TTPs used by the threat actor group known as Boogeyman by performing forensic analysis on a copy of a phishing email and a memory dump file. 

**Environment:** Linux 

**Tools Used:**
- Volatility
- Bash
- Olevba (tool used for extracting VBA macros from Microsoft Office Documents)

**Notable Artifacts:**
- copy of phishing email ```Resume-Application for Junior IT Analyst Role.eml```
- Memory dump file ```WKSTN-2961.raw```


***Goals:***
- Gain experience in using the forensic tool volatility
- Demonstrate skill in using volatility to successfully identify TTPs of a threat actor group's attack chain.
- Shore up and enhance report writing


# Start of Investigation 

