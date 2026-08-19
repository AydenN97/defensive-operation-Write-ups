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

**Task 2:** 
