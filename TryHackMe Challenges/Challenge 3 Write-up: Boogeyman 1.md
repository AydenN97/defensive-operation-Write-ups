# Title: Challenge 3 Write-Up: Boogeyman 1

# Introduction

***Scenario Overview:***  🛡️ ﻿Uncover the secrets of the new emerging threat, the Boogeyman threat actor 

***Objective:***  🔎 Analyze the Tactics, Techniques, and Procedures (TTPs) executed by a threat group, from obtaining initial access until achieving its objective. 

**Environment and Tools Used:** 
- Linux
- jq
- Wireshark
- Tshark
- Thunderbird
- Lnkparser3 
- Linux command line tools such as awk, grep, sed, and base64

**Given Artifacts:**
- copy of a phishing email (dump.eml)
- Powershell Logs from Julianne's Workstation
- Packet Capture From the same workstation (Capture.pcap)

***Goals:***
- Gained familiarity in using Wireshark and TShark to determine if and to which extent is an particular endpoint compromised.  
- Extract TTPs using Wireshark, TShark, and Linux command line tools
- Demonstrate experience in using Wireshark and TShark.
- Demonstrate skill and experience in analyzing a phishing email by analyzing headers and body of the email in the original HTML.


# Start of the Investigation 


### Task 1: Email Analysis 

If we remember from the introduction, we are given an email file (dump.eml) that may include malicious attachments. We can analyze the email using Thunderbird. 
We extract the following information from dump.eml by looking at the headers, message body as original HTML: We make sure to pay close attention to the following sections: DKIM-Signatures, From, To, Received From, Return=Path and any attachments.
Some details gathered: 
- Email address used to send the phishing email: *agriffin@bpakcaging[.]xyz*
- Email Address of victim: *julianne.westcott@hotmail[.]*
- Third-Party mail relay service used: *elasticemail*
- 

