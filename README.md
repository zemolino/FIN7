# Analysis of FIN7 TTPs:
FIN7 is a sophisticated threat actor known for financially motivated attacks against organizations. Their TTPs include a variety of techniques across different stages of the attack lifecycle. Let's focus on a few key techniques and propose enhancements for detection:

**A. Spearphishing:**
* FIN7 often utilizes spearphishing emails with malicious attachments or links to deliver malware.
* They use social engineering to craft convincing emails.

**B. Execution:**
* FIN7 leverages PowerShell for various tasks, such as downloading payloads and executing commands.

**C. Persistance:**
* 

**D. Privilege Escalation:**
* 

**E. Defense Evasion:**
*  

**F. Credential Access:**
* 

**G. Discovery:**
* 
	
**H. Lateral Movement:**
* 

**H. Collection:**
* 

**H. Command and Controlt:**
* 

**H. Exfiltration:**
* 

### Detection Rule Proposals:

**A. Initial Access:**
- **Enhancement:** Develop email filtering rules based on known indicators of compromise (IoCs) and use machine learning to detect anomalies in email content.

- **Detection Rule:**

    **Spearphishing Attachment (T1566.001):**

    FIN7 uses macro enabled files go gain access to the network. If the macros are not enabled the attacker will try to convice target to enable them to run the scripts in the background. This query detects when a macro attachment is opened that came from a rare sender from the last 7 days.

    **Defender For Endpoint**
    ```
    // Adjust the threshold based on your organisation.
    let RareSenderThreshold = 10;
    let LookupPeriod = 7d;
    let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb']);
    // If you also want to include older attachments use
    // let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb', 'doc', 'xsl', 'svg']);
    // Step 1
    let RareMacroSenders = EmailAttachmentInfo
    | where Timestamp > ago(30d)
    // Extract the file extension for each filename
    | extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
    // Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
    | where isnotempty(FileExtension) and isnotempty(SHA256)
    // Filter only on marco extensions
    | where FileExtension in~ (MacroExtensions)
    | summarize TotalMacroAttachmentsSend = dcount(NetworkMessageId) by SenderObjectId
    // Filter on rare senders
    | where TotalMacroAttachmentsSend < RareSenderThreshold
    | project SenderObjectId;
    // Step 2
    let RecievedMacros = EmailAttachmentInfo
    | where Timestamp > ago(LookupPeriod)
    // Filter on rare senders. Senders that often user macro's are filtered.
    | where SenderObjectId in (RareMacroSenders)
    // Extract the file extension for each filename
    | extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
    // Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
    | where isnotempty(FileExtension) and isnotempty(SHA256)
    // Filter only on marco extensions
    | where FileExtension in~ (MacroExtensions)
    | project SHA256;
    // Step 3
    DeviceFileEvents
    | where ActionType == 'FileCreated'
    // Search for devices that have FileEvents with macros recieved from emails.
    | where SHA256 in (RecievedMacros)
    | summarize TotalDevices = dcount(DeviceName), FileLocations = make_set(FolderPath) by SHA256
    // Collect the email events, to enrich the results. Step 4
    | join kind=inner (EmailAttachmentInfo | project RecipientEmailAddress, NetworkMessageId, SHA256) on $left.SHA256 == $right.SHA256
    | join kind=inner (EmailEvents | project SenderFromAddress, Subject, NetworkMessageId, EmailDirection) on $left.NetworkMessageId == $right.NetworkMessageId
    // Only search for inbound mail
    | where EmailDirection == 'Inbound'
    | summarize ['Targeted Mailboxes'] = make_set(RecipientEmailAddress) by SHA256, TotalDevices, tostring(FileLocations), Subject, SenderFromAddress
    ```
    #### References
    - https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519
    - https://support.microsoft.com/en-us/topic/outlook-blocked-access-to-the-following-potentially-unsafe-attachments-c5c4a480-041e-2466-667f-e98d389ff822
    - https://www.bleepingcomputer.com/news/security/the-most-common-malicious-email-attachments-infecting-windows/
    - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Office%20365/Email%20-%20MacroAttachmentOpenedFromRareSender.md
    
    **Spearphishing Link (T1566.002):**
    
    The EmailClusterId which can be assigned to a mail is the identifier for the group of similar emails clustered based on heuristic analysis of their contents. Therefore this identifier can be leveraged to find related mails. This can for example be from a different sender or the content of the mail has changed from Hello Bob to Hello Alice but the rest of the contents has stayed the same. This query searches for mails that have the same EmailClusterId but have different senders. Furthermore only emails that contain a URL are selected by joining the EmailUrlInfo table.

    ```
    let RareDomainThreshold = 20;
    let TotalSenderThreshold = 1;
    let RareDomains = EmailEvents
    | summarize TotalDomainMails = count() by SenderFromDomain
    | where TotalDomainMails <= RareDomainThreshold
    | project SenderFromDomain;
    EmailEvents
    | where EmailDirection == "Inbound"
    | where SenderFromDomain in (RareDomains)
    | where isnotempty(EmailClusterId)
    | join kind=inner EmailUrlInfo on NetworkMessageId
    | summarize Subjects = make_set(Subject), Senders = make_set(SenderFromAddress) by EmailClusterId
    | extend TotalSenders = array_length(Senders)
    | where TotalSenders >= TotalSenderThreshold
    ```
    #### References
    - https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide
    - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Office%20365/Email%20-%20PotentialPhishingCampaign.md
    
**A. Execution:**
- **Detection Rule:**

    **PowerShell(T1059.001):**
    **Splunk:**
    **Detect Empire with PowerShell Script Block Logging:**
    The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify suspicious PowerShell execution. Script Block Logging captures the command sent to PowerShell, the full command to be executed. Upon enabling, logs will output to Windows event logs. Dependent upon volume, enable on critical endpoints or all.
     ```
    search: '`powershell` EventCode=4104  (ScriptBlockText=*system.net.webclient* AND
  ScriptBlockText=*frombase64string*) | stats count min(_time) as firstTime max(_time)
  as lastTime by Opcode Computer UserID EventCode ScriptBlockText | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `detect_empire_with_powershell_script_block_logging_filter`'
  ```
  #### References
     - https://github.com/splunk/security_content/blob/develop/detections/endpoint/detect_empire_with_powershell_script_block_logging.yml
     - https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
      
     **KQL:**
     An attacker uses the System.Management.Automation DLL to execute powershell commands, instead of the PowerShell.exe
    ```
    DeviceImageLoadEvents
    | where FileName =~ "System.Management.Automation.dll" or FileName =~ "System.Management.Automation.ni.dll"
    | where InitiatingProcessFolderPath !~ "C:\\Windows\\System32\\WindowsPowerShell\\v1.0" and InitiatingProcessFolderPath !~ "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0"  and (InitiatingProcessFileName !~ "powershell.exe" or InitiatingProcessFileName !~ "powershell_ise.exe")
    // The RemoteFXvGPUDisablement.exe is for GPU virtualization, MS recommends to remove this service as of July 2020. 
    | where InitiatingProcessFolderPath !~ "C:\\Windows\\system32" and InitiatingProcessFileName !~ "RemoteFXvGPUDisablement.exe"
    // exclusions below can be enabled if you're using visual studio 
    //| where InitiatingProcessFolderPath !contains "C:\\Windows\\Microsoft.NET\\Framework" and InitiatingProcessFileName !~ "devenv.exe"
    //| where InitiatingProcessFolderPath !contains "\\Microsoft Visual Studio\\2019\\Community\\Common7\\ServiceHub\\Hosts\\ServiceHub.Host.CLR.x86" and InitiatingProcessFileName !startswith "servicehub"
    //| where InitiatingProcessFolderPath !contains "\\Microsoft Visual Studio\\2019\\Community\\Common7\\IDE" and InitiatingProcessFileName !~ "mscorsvw.exe" and InitiatingProcessParentFileName !~ "ngen.exe"
    | project Timestamp,DeviceName,InitiatingProcessAccountName,ActionType,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessIntegrityLevel,FileName,InitiatingProcessParentId,InitiatingProcessId
    ```
    #### References
     - https://github.com/FalconForceTeam/FalconFriday/blob/master/Execution/T1059.001-WIN-001.md

**C. Persistance:**
- **Detection Rule:**
T1543.003 - Create or Modify System Process: Windows Service:

     **KQL:**
    ```
    let netevents=DeviceNetworkEvents 
    | where ActionType == "InboundConnectionAccepted"
    | where InitiatingProcessFolderPath == @"c:\windows\system32\services.exe"
    // IMPORTANT There is some legitimate use for maintenance by support teams, filter their IP addresses/blocks below
    | where not(RemoteIP has_any ("maintenance-ip-1","maintenance-ip-2","maintenance-ip-3"))
    | project Timestamp,DeviceId,ActionType,InitiatingProcessFolderPath, DeviceName, RemoteIP, InitiatingProcessId;
    let regevents=DeviceRegistryEvents 
    | where RegistryKey contains @"\System\CurrentControlSet\Services" or RegistryKey contains @"\System\ControlSet001\Services"
    | where ActionType contains "Created"
    |project DeviceId, ActionType, RegistryKey, RegistryValueType,RegistryValueData, InitiatingProcessFolderPath,InitiatingProcessId, DeviceName;
    let rpcservices = 
    	netevents
    	| join kind=leftouter  (regevents) on DeviceId, InitiatingProcessFolderPath,InitiatingProcessId;
    rpcservices
    | project Timestamp,DeviceName,RemoteIP,ActionType1 ,RegistryKey, RegistryValueType, RegistryValueData
    |summarize count() by RemoteIP
    ```
    #### References
     - https://github.com/FalconForceTeam/FalconFriday/blob/master/Persistence/T1543.003-WIN-001.md

**D. Privilege Escalation:**
- **Detection Rule:**
T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching:
     **KQL:**
    ```
    let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
    DeviceProcessEvents
    | extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
    | where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
    ```
    #### References
     - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/Linux/Linux%20-%20UsersAddedToSudoersGroup.md

**E. Defense Evasion:**
- **Detection Rule:**
T1027 Obfuscated Files or Information - PowerShell Encoded Commands Executed By Device:
     **KQL:**
    ```
    let EncodedList = dynamic(['-encodedcommand', '-enc']); 
    // For more results use line below en filter one above. This will also return more FPs.
    // let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
    let TimeFrame = 48h; //Customizable h = hours, d = days
    DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
    | where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
    | extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
    | extend DecodedCommandLine = base64_decode_tostring(base64String)
    | where not(isempty(base64String) and isempty(DecodedCommandLine))
    | summarize TotalEncodedExecutions = count() by DeviceName
    | sort by TotalEncodedExecutions
    ```
    T1027 Obfuscated Files or Information - All Encoded Powershell Commands:
    **KQL:**
    ```
    let EncodedList = dynamic(['-encodedcommand', '-enc']); 
    // For more results use line below en filter one above. This will also return more FPs.
    // let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
    let TimeFrame = 48h; //Customizable h = hours, d = days
    DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
    | where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
    | extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
    | extend DecodedCommandLine = base64_decode_tostring(base64String)
    | extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
    | where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
    | summarize UniqueExecutionsList = make_set(DecodedCommandLineReplaceEmptyPlaces) by DeviceName
    | extend TotalUniqueEncodedCommandsExecuted = array_length(UniqueExecutionsList)
    | project DeviceName, TotalUniqueEncodedCommandsExecuted, UniqueExecutionsList
    | sort by TotalUniqueEncodedCommandsExecuted
    ```
    #### References
     - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedCommandsByDevice.md
     - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedCommandsExecuted.md

**E. Credential Access:**
- **Detection Rule:**
T1110 Brute Force - Password change after succesful brute force:
    **KQL:**
    ```
    let FailedLogonsThreshold = 20;
    let SuccessfulLogonsThreshold = 1;
    let TimeWindow = 15m;
    // Time between the succesful brute force and password change. Difference should be added in minutes
    let SearchWindow = 120;
    IdentityLogonEvents
    // Filter emtpy UPN
    | where isnotempty(AccountUpn)
    | summarize
        TotalAttempts = count(),
        SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
        FailedAttempts = countif(ActionType == "LogonFailed")
        by bin(Timestamp, TimeWindow), AccountUpn
    // Use variables to define brute force attack
    | where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold
    // join password changes
    | join kind=inner (IdentityDirectoryEvents
        | where Timestamp > ago(30d)
        | where ActionType == "Account Password changed"
        | where isnotempty(TargetAccountUpn)
        | extend PasswordChangeTime = Timestamp
        | project PasswordChangeTime, TargetAccountUpn)
        on $left.AccountUpn == $right.TargetAccountUpn
    // Collect timedifference between brute force (note that is uses the bin time) and the password change
    | extend TimeDifference = datetime_diff('minute', PasswordChangeTime, Timestamp)
    // Remove all entries where the password change took place before the brute force
    | where TimeDifference > 0
    | where TimeDifference <= SearchWindow
    ```
    
    T1110.003 - Brute Force: Password Spraying
    **KQL:**
    ```
    let thresholdForUniqueFailedAccounts = 20;
    let upperBoundOfFailedLogonsPerAccount = 10;
    let ratioSuccessFailedLogons = 0.5;
    let timeframe = 1d;
    DeviceLogonEvents
    | where Timestamp >= ago(timeframe)
    | where LogonType != "Unlock" and ActionType in ("LogonSuccess", "LogonFailed")
    | where not(isempty( RemoteIP) and isempty( RemoteDeviceName))
    | extend LocalLogon=parse_json(AdditionalFields)
    | where RemoteIPType != "Loopback"
    | summarize SuccessLogonCount = countif(ActionType == "LogonSuccess"), FailedLogonCount = countif(ActionType == "LogonFailed"),
        UniqueAccountFailedLogons=dcountif(AccountName, ActionType == "LogonFailed"), FirstFailed=minif(Timestamp, ActionType == "LogonFailed"),
        LastFailed=maxif(Timestamp, ActionType == "LogonFailed"), LastTimestamp=arg_max(Timestamp, tostring(ReportId)) by RemoteIP, DeviceName //Remote IP is here the source of the logon attempt.
    | project-rename IPAddress=RemoteIP
    | where UniqueAccountFailedLogons > thresholdForUniqueFailedAccounts and SuccessLogonCount*ratioSuccessFailedLogons < FailedLogonCount and UniqueAccountFailedLogons*upperBoundOfFailedLogonsPerAccount > FailedLogonCount 
    ```
    
