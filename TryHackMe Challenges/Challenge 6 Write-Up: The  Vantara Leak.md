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




# Start of Investigation 

**Background:** 
Prior to starting the investigation, our lead tells us that our forensic workstation contains KAPE artifacts located here: ```C:\Users\DFIRUser\Vantara-Artefacts.zip```. 
