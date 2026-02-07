# LogJammer Sherlock | Hack The Box Walkthrough
> ## Using Windows Event Viewer to analyze Security, System, PowerShell, Windows Defender, and Firewall Sysmon logs

### [>>GOOGLE DOC VERSION <<](https://docs.google.com/document/d/1Cfj9ygWGTZB16vZoHgMVAgPtaJwHfJhfc1LwzzC13FE/edit?usp=sharing) (Originally posted on Medium.com)

*Completed 11/2/2025* -- *Jack Dignam*

- - - 
<p align="center"> <img width="321" height="298" alt="1_uo3bTIBPRpBLIQLrVu-1Gg" src="https://github.com/user-attachments/assets/6ed71099-2f30-4417-a868-6ee4e3ce2268" />
<p align="center"> https://app.hackthebox.com/sherlocks/557

# Introduction
My third [Hack The Box](https://www.hackthebox.com/) Sherlock walkthrough is [LogJammer](https://app.hackthebox.com/sherlocks/557)! This easy-level lab is the 7th challenge from the **Intro to Blue Team** track that focuses on **Windows Event Viewer**. 
It showcases how to filter for logs and teaches new *Sysmon* event identifiers.

LogJammer is a direct sequel to the third challenge, Unit42, covering log filtering even more in-depth. You can view my walkthrough of **Unit42** here: 

- [github.com/jackdignamit/Unit42-Sherlock-Walkthrough](https://github.com/jackdignamit/Unit42-Sherlock-Walkthrough)

If you find this walkthrough helpful, please feel free to drop a follow. Thank you for your consideration, now let's do this investigation!

---

# Challenge Scenario
> You have been presented with the opportunity to work as a junior DFIR consultant for a big consultancy.
> However, they have provided a technical assessment for you to complete.
> The consultancy Forela-Security would like to gauge your Windows Event Log Analysis knowledge.
> We believe the Cyberjunkie user logged in to his computer and may have taken malicious actions.
> Please analyze the given event logs and report back.

In this challenge, we are a junior DFIR consultant who needs to complete an assignment using Windows Event Viewer. 
A user, **CyberJunkie**, has taken advantage of a computer to perform malicious actions on our network. It is our job to conduct a thorough investigation and complete the tasks.
This lab will utilize *Windows Event Viewer* to view *Sysmon* Event logs. Each log is identified with an **Event ID**. For this particular challenge, these are the event IDs we will be filtering for:

```
Event ID 104: a Windows event log has been cleared
Event ID 2004: a new rule was added to the Windows Defender Firewall
Event ID 4103: a PowerShell module logging event occurred, such as cmdlet invocations or variable initialization.
Event ID 4624: indicates a successful logon to a computer.
Event ID 4698: a new scheduled task was successfully created
Event ID 4719: logs when a system audit policy is successfully changed
```
--- 

## Setup the Lab Environment:
As a good rule of thumb before any simulated investigation, it is a smart idea to use a **virtual machine**. 
This ensures the environment is completely isolated and safe. For this particular lab though, it is completely optional as we are only filtering logs.

If you need instructions on installing a Windows 10 virtual machine of your own, you can follow this tutorial: 

[![](https://github.com/user-attachments/assets/e9091b5f-0e05-4b4c-9272-0e1e7e0ab851)](https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS)

https://youtu.be/CMGa6DsGIpc?si=Dif9kTTge-xOandS

From your virtual machine, download the Hack the Box file and unzip it onto your desktop. 
You can then double click on the **`.evtx files`** to open them up in Windows Event Viewer.

--- 
# Walkthrough
## Task 1: When did the CyberJunkie user first successfully log into his computer? (UTC)
Now that Windows Event Viewer is open and all the event files are ingested, select the **Security tab** under **Saved Logs** on the left-hand side. 
From here, all security audit logs can be located such as login attempts, privilege usage, object access, etc.

According to our challenge scenario from earlier, a user named **CyberJunkie** has logged into a computer and attempted to utilize it. We can discover the time they first accessed it by filtering for **Event ID: 4624**.

On the right-hand side, click on `Filter Current Log…` and enter **4624** in the Event ID box.

<img width="679" height="688" alt="1_GrlvkUwzXh6FWldhYDSklg" src="https://github.com/user-attachments/assets/da385b87-dcbc-44e3-95a8-ad2632712952" />

Event ID 4624 filters for all successful logons to a computer. If we look for the first event, we can discover the timestamp for when it occurred by viewing the Sysmon details:

<img width="960" height="1228" alt="1_w0kMhQu2mFMNNK56Fi9I-w" src="https://github.com/user-attachments/assets/df6af3cd-c1c1-4edf-8130-2fb1256295d3" />

As it lists, the first login SystemTime was `2023–03–27T14:37:08.6008290Z` aka: **27/03/2023 14:37:09**.

<img width="1000" height="143" alt="1_sq61B6FSZ_aCVLDklpX69w" src="https://github.com/user-attachments/assets/88248d66-07ee-4570-a4ba-d3736134caeb" />

--- 

## Task 2: The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?
Firewall rules are a high-value move for an attacker as it opens up the entire network for vulnerability, as firewalls serve as the network's gatekeeper. 
This can result in a user maintaining persistence by remotely accessing an internal host or evading detection altogether.

On the left-hand side, select the **Firewall** tab, and filter for Event ID **2004**. This event lists all the new rules that were added.

<img width="1000" height="581" alt="1_bKMImWSyo_TtBdTOAq2tpg" src="https://github.com/user-attachments/assets/b28714b3-4a53-4e9e-ab97-7e01a436f95e" />

It returns several logs with firewall rules being added for Microsoft Edge, Firefox, Metasploit, and more. 
The very latest log would be the first place to look as the firewall rule was added after the attacker gained access. The log's rule name is Metasploit C2 Bypass.

We can assume that the **Metasploit C2 Bypass** is the firewall rule the attacker added because Metasploit is a widely used penetration-testing framework. It contains exploit modules, payloads, and post-exploitation tools.

<img width="1000" height="140" alt="1_IGwlvIliidxTAYwc4SzvPg" src="https://github.com/user-attachments/assets/bc8c257a-99e9-4f69-aceb-73f9949ed89f" />

--- 

## Task 3: What's the direction of the firewall rule?
In the rule name "Metasploit C2 Bypass", C2 stands for **Command-and-Control**. 
Metasploit is often used with command and control servers for remote control sessions and persistence.

The attacker wants to maximize the amount of access they can gain with Metasploit, so they would have to set the firewall rule to allow **Outbound** connections. 
This lets the attacker create an exception for IDS/IPS or proxy rules, whitelist processes or ports (such as msfconsole TCP/4444), and allow established connections.

<img width="612" height="297" alt="1_ejWhYLt7-oh1TR6HyugfQg" src="https://github.com/user-attachments/assets/bc530e60-8102-496a-aa48-05480ef77abb" />
<img width="1000" height="142" alt="1_tq0o78lxyNJ5eJD1wukODQ" src="https://github.com/user-attachments/assets/66f99514-c187-4938-ba74-f83160590307" />

--- 

## Task 4: The user changed audit policy of the computer. What's the Subcategory of this changed policy?
Windows audit policy is a security feature that controls what and how security-related events are logged on a system to help administrators monitor, detect, and investigate potential breaches. 
If the Windows audit policy is changed, then an attacker can disable these logs, hiding malicious activities such as creating backdoors for persistence.

**Event ID 4719** logs when a system audit policy is successfully changed. System security changes would be found in the **Security tab**. Once there, we can filter for event ID 4719 and view the results.

<img width="1000" height="78" alt="1_kDvjzVzzgE2N1WJBr0546g" src="https://github.com/user-attachments/assets/2c0a0a2d-b9c9-4222-864c-fdc3332fdea1" />

There is only one audit change log, which reveals in its details that it alters Object Access. 
Object access logs **successful** and **unsuccessful user attempts** to access objects or processes. This includes reading or writing a file, deleting folders, or modifying registry keys.

<img width="592" height="370" alt="1_x6OTDiyaP_CFEdIXCow6Xg" src="https://github.com/user-attachments/assets/81961d72-fe67-4ce1-b80c-dae405f5138e" />

The subcategory for the audit change is **Other Object Access Events**.

<img width="1000" height="144" alt="1_E95xuMoFV_GV5Hze7SrLeA" src="https://github.com/user-attachments/assets/22569518-10db-4dee-a85b-50e18ebf778a" />

--- 

## Task 5: The user "CyberJunkie" created a scheduled task. What's the name of this task?
Remaining in the **security tab**, we filter for **Event ID 4698**.
This ID indicates that a new scheduled task was successfully created. It displays only one event. In the details, it reveals the task name of `HTB-AUTOMATION`.

<img width="652" height="410" alt="1_UwiInEQBPCHpxKC7becRhQ" src="https://github.com/user-attachments/assets/cf12164d-cd7c-4b66-a65d-5ff2756cc886" />

<img width="1000" height="147" alt="1_wMNX3j6mt-t_lhDDAY4Y9A" src="https://github.com/user-attachments/assets/538f7d17-96db-4eea-8e09-11f4652e4497" />

--- 

## Task 6: What's the full path of the file which was scheduled for the task?
A malicious user like CyberJunkie can utilize scheduled tasks to **make files run automatically**, even after a reboot or user logoff. 
This results in persistence or even privilege escalation depending on the executed file.

If the scheduled task contains a malicious file with higher privileges than the current user, then the file could run with admin rights, potentially bypassing **User Account Control (UAC)** prompts.

On the scheduled task log, click on the **details tab** and use friendly view to see the **TaskContent**. It displays the file set to run under the <command> XML tag.

<img width="1000" height="391" alt="1_BAVKMatpugwciVXTsibTUw" src="https://github.com/user-attachments/assets/4f5b9b66-a325-4a56-b49e-5adb45c7f721" />

The file name is revealed under: `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`

<img width="1000" height="144" alt="1_FLN1k06XOIJn87OArvdCPQ" src="https://github.com/user-attachments/assets/90568011-f4fc-40e8-bbf6-7baeca23e050" />

--- 

## Task 7: What are the arguments of the command?
On the same screen, `<Arguments>` are displayed to the right of the `<command>` XML tag.

<img width="547" height="77" alt="1_7tmsZyxPiA_IKx8h5yddCA" src="https://github.com/user-attachments/assets/8ecdea43-4fbb-4645-8481-6fc3f4afbc8a" />

It reveals an email, likely set as a Command & Control (C2) identifier. 
Malware sometimes uses unique strings (like emails) to identify a specific target system. This helps differentiate reports from multiple compromised hosts.

The full argument is: **-A cyberjunkie@hackthebox.eu**

<img width="1000" height="143" alt="1_XZSmUXL4OMTM7ictECZafA" src="https://github.com/user-attachments/assets/68a7cd5d-5e89-4c9b-9520-c60252c83ac6" />

--- 

## Task 8: The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?
To view Windows Defender operations, click the **Windows Defender-Operational** tab under *Saved Logs*. 
The output reveals 444 events with the majority being informational. 
Windows Defender's antivirus labels logs that detect malware as **Warnings**. In the output, we can see two of them.

<img width="1000" height="581" alt="1_t1t2Wupa-dbE3WDEJo5JyQ" src="https://github.com/user-attachments/assets/196fdcf0-ea44-428a-86a3-56ceb53df706" />

In the details of the flagged logs, it is revealed that the tool detected is named **Sharphound**.

<img width="304" height="32" alt="1_7833IqyK5JqCiyvCdoS6pg" src="https://github.com/user-attachments/assets/a570c50e-c2c9-4f00-956d-5c34887e926d" />

<img width="1000" height="144" alt="1_bo4T1aqFlKf3Q9ONMkBeEQ" src="https://github.com/user-attachments/assets/8c5da33e-3656-495e-9e6b-7b64ed88e30c" />

--- 

## Task 9: What's the full path of the malware which raised the alert?
On the same screen from the previous task, if we click on the details tab we can see the exact file location of the flagged malware: 
`C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`

<img width="1000" height="295" alt="1_GldW47k-zBhys1zbh0VLvw" src="https://github.com/user-attachments/assets/e1c917f3-7e40-4730-aa3a-c683c3076bf7" />

<img width="1000" height="147" alt="1_DSx4pvbgbjy1r-4vTunaTw" src="https://github.com/user-attachments/assets/f5ec3a01-3c1d-42b6-8884-b1c5796ad355" />

--- 

## Task 10: What action was taken by the antivirus?
Actions performed by the antivirus are displayed in events labeled as **information**:

<img width="611" height="229" alt="1_dizBymT_Jj2HGmQFT69sQg" src="https://github.com/user-attachments/assets/9ca85bf2-fbb2-483b-aaa9-27d5ba021456" />

The action taken by the antivirus follows immediately after the initial detection. In the general tab, it reveals the action was a **quarantine**. 
When Windows Defender quarantines a file, the file is moved to a **special protected folder** where it cannot run or interact with your system. 
It is a safety measure, not a deletion. It allows the file to be recovered if needed.

<img width="907" height="623" alt="1_w3rLuBq62BJExLmWYVh-DA" src="https://github.com/user-attachments/assets/b4f3ad1a-da37-465a-80c0-519575a241e3" />

<img width="1000" height="146" alt="1_Ihg3zlKhhS_gNnk4BJooPw" src="https://github.com/user-attachments/assets/53585b25-2c74-4d67-854e-3f326082dcec" />

--- 

## Task 11: The user used PowerShell to execute commands. What command was executed by the user?
The user used PowerShell to execute commands, which in this case is likely for informational purposes or reconnaissance. 
The attacker has already established some methods of privilege escalation and persistence.

If we select the **PowerShell-Operational** tab under our Saved Logs, we can use **Event ID 4103** to filter for PowerShell modules logging, such as cmdlet invocations or variable initialization.

<img width="860" height="386" alt="1_HfD0MlqXHwsQ07GzgXu_CQ" src="https://github.com/user-attachments/assets/2b5348e8-e8e6-405a-a850-1d665e362705" />

This returns 11 results, most of which are uninteresting and contain nothing related to the malicious user. 
The only exception is the one at `2023-03–27 14:58:33` which contains a command execution relating to the attacker's file.

<img width="1000" height="244" alt="1_A57jYvBqZKk-_8d_4_n-Ng" src="https://github.com/user-attachments/assets/7a569f63-6f0d-4449-bce7-43a8c054ef5d" />

The attacker entered `"Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1"` into PowerShell, likely to verify integrity of the file's hash before execution.

<img width="1000" height="143" alt="1_SA-6KVPDIaTIdpgIudSMvA" src="https://github.com/user-attachments/assets/97004fe1-9a08-468f-a0bd-6800433e3698" />

--- 

## Task 12: We suspect the user deleted some event logs. Which Event log file was cleared?
We can view clearing of event logs under the **Security** event file under *Saved Logs*. Filtering for **Event ID 104** will display all logs that have been cleared.

<img width="1000" height="603" alt="1_ZSMdcpEq9Tav9sboJFr6HQ" src="https://github.com/user-attachments/assets/adeb5c81-a1c4-4c84-b961-003cc9fb13cf" />

The latest log is the most relevant as it occurs after the initial malicious user's infiltration. 
In the details tab, it displays under *LogFileCleared* that the channel "**Microsoft-Windows-Windows Firewall With Advanced Security/Firewall**" was cleared.

<img width="1000" height="140" alt="1_qANsTzqjusJjA9Zit7ibKQ" src="https://github.com/user-attachments/assets/2d856e6a-a383-46a7-a223-db2a6fdc160d" />

---
# Conclusion 
<img width="874" height="805" alt="1_Vsm4iQMCCMAJYT2zz1g3Tw" src="https://github.com/user-attachments/assets/1c13ba3a-9359-4cef-b66b-456c2a986515" />

The **LogJammer Sherlock** challenge from *Hack The Box* offers many essential skills in filtering Sysmon logs in Windows Event Viewer. 
It teaches how to import `.evtx files`, filter using Event IDs, and analyze Sysmon logs to conduct a thorough investigation. 
These are all important skills in Blue team operations and greatly assist in threat hunting, faster investigations, and timeline building.

Using these skills, we discovered the user "**CyberJunkie**" performing many malicious activities on a compromised host. 
This includes reconnaissance with PowerShell, bypassing firewall configurations, utilizing Metasploit for persistence, and potentially privilege escalation by task scheduling malware. 
The malware used by the attacker was flagged and quarantined by Windows Defender.

If you found this walkthrough helpful, please feel free to drop a follow. Thank you for reading!

## References
Challenge: https://app.hackthebox.com/sherlocks/557

Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

