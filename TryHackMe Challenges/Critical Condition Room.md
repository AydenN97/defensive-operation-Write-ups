TryHackMe Room Link: https://tryhackme.com/room/criticalcondition

*Purpose*: Document completed Sigma Rules needed to complete the critical condition room in TryHackMe.


## Completed Sigma Rule for PR #1

```yaml
title: VPN Appliance Worker Process Spawns Suspicious Child Process
id: 4eb5804a-4827-4309-9e31-21ce8f52e873
status: experimental
description: Detects the NetGate Secure Access VPN appliance worker process launching a command interpreter or living off the land binary, consistent with post exploitation following an authentication bypass and remote code execution chain.
author: jordan-blake
logsource:
    product: windows
    category: process_creation

detection:
    selection_parent:
        ParentImage|endswith:
            - '\NetGateWorker.exe'
            - '\NetGateAgent.exe'

    selection_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'whoami'
            - '/all'

    selection_recon:
        Image|endswith: '\cmd.exe'
        CommandLine|contains:
            - 'ipconfig'
            - 'net view'
            - 'nltest'
            - 'certutil'

    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '

    selection_suspicious_tools:
        Image|endswith:
            - '\certutil.exe'
            - '\msiexec.exe'

    condition: selection_parent and (selection_cmd or selection_recon or selection_suspicious_tools or selection_powershell)

falsepositives:
    - Legitimate VPN appliance maintenance
    - Authorized administrative activity
    - Approved software installation

level: high
```

## Sigma Rule for PR #2

