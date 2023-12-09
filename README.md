# Analysis of FIN7 TTPs:
FIN7 is a sophisticated threat actor known for financially motivated attacks against organizations. Their TTPs include a variety of techniques across different stages of the attack lifecycle. Let's focus on a few key techniques and propose enhancements for detection:

**A. Spearphishing:**
* FIN7 initiates their attacks through spear-phishing campaigns, utilizing email attachments embedded with exploits to breach the target system.
* They use social engineering to craft convincing emails.

**B. Execution:**
* Upon successful entry, FIN7 executes their attacks using diverse techniques, including native API, PowerShell, service execution, user execution, Windows Component Object Model (COM), Distributed COM, and Windows Management Instrumentation (WMI). Mshta utility and scheduled tasks are also exploited for code execution.

**C. Persistance:**
* To maintain a presence within the system, FIN7 creates new services, adds programs to startup folders, and manipulates registry run keys. Application shimming databases and process hooking are also utilized for persistence.

**D. Privilege Escalation:**
* For elevated privileges, FIN7 bypasses Windows User Account Control (UAC) mechanisms, employs new services, and exploits valid accounts. On Linux systems, they may use the sudo program, and on Windows, inject code into processes and manipulate DLL loading order.

**E. Defense Evasion:**
*  To avoid detection, FIN7 employs various evasion techniques such as code signing, deobfuscation, masquerading, obfuscation of files and information, software packing, and process injection. Guardrails, abused utilities, evasion of virtualization, and injecting code into hollowed processes are also used.

**F. Credential Access:**
* FIN7 steals credentials through techniques like credential dumping and input capture. Credential dumping involves extracting hashed or clear-text credentials, while input capture targets API or web portals. Hooking is another credential access tactic employed.

**G. Discovery:**
* During the discovery phase, FIN7 gains knowledge about the system by collecting information on open application windows, running processes, IP addresses, hardware details, network configuration, system owners, users, accounts, files, directories, group permissions, and registries.
	
**H. Lateral Movement:**
* FIN7 moves laterally through the network by logging in via Remote Desktop Protocol (RDP), copying files, and exploiting Windows admin shares. They may also log into services with remote connections and use stolen password hashes through the "pass the hash" method.

**I. Collection:**
* After identifying key assets, FIN7 collects data from local sources using input and screen capture. In some cases, collected data is staged in a specific location for subsequent exfiltration.

**J. Command and Control:**
* Communication with compromised systems involves bypassing firewalls, utilizing common ports, employing connection proxies, remotely copying files, blending in with existing network traffic, and using standard cryptographic protocols. Legitimate programs and remote access software are sometimes used for command and control.

**K. Exfiltration:**
* In the final phase, FIN7 exfiltrates stolen data through command-and-control channels, with the data potentially compressed and encrypted to avoid detection.

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
**F. Discovery:**
- **Detection Rule:**
T1040 Network Sniffing- Windows Network Sniffing:

    **KQL:** 
    ```
    DeviceProcessEvents
    | where FileName == "PktMon.exe"
    | project Timestamp, DeviceName, ProcessCommandLine
    ```
    
**H. Lateral Movement:**
- **Detection Rule:**
Potential Lateral Movement with Non-Personal Privileged Account

    **KQL:** 
    ```
    // Author: Cyb3rMonk(https://twitter.com/Cyb3rMonk, https://mergene.medium.com)
    // Link to original post: https://mergene.medium.com/building-a-custom-ueba-with-kql-to-hunt-for-lateral-movement-7459a899091
    //
    //              How to use this query:
    //              Modify the "Service account condition" sections according to your environment. Set query time to 15d or 30d.
    //              It is quite suspicious if a service account is used from a new source (espcially from a workstation)
    //              If you want to see the results where there is no associated alert, change the value ShowResultsWithNoAlerts to 'YES'. Otherwise, set it to 'NO'.
    //              
    //              In an attack involving lateral movement or valid accounts, you might expect to see at least one alert related to either the source device, the destination device or the service account. 
    //              Service accounts are expected to be used on the same devices. If the account was seen on a new source device (IsSourcedUsedBefore=No), it may be anomalous.
    //              Service accounts are usually seen on servers. If the source device type is workstation, it's quite anomalous. Check IsSourcedUsedBefore info.
    //              Some service accounts used to deploy stuff on all devices. SourceCount and TargetCount gives an idea about the account usage/type.
    //              
    //              Explanations of the custom fields in the results:
    //              IsSourceUsedBefore/IsTargetUsedBefore: if the acount has used Source/Target device before. 
    //              AccountSourceCount/AccountTargetCount: Number of distinct Source/Target Devices that the account has used before.
    //
    let ShowResultsWithNoAlerts = "YES";
    let lookback = 30d;
    let timeframe = 1d;
    // Generate building blocks
    // Whitelisted alerts. (Some alerts may keep popping up as false positives, add the title info to the list)
    let whitelisted_alerts = dynamic(["EICAR_Test_File"]);
    // 1. Generate list of Servers based on OSPlatform info
    let server_list = 
        DeviceInfo
        | where Timestamp > ago(lookback)
        | where OSPlatform startswith "WindowsServer"
        | summarize make_set(DeviceName)
        ;
    // 2. Generate list of Workstations based on OSPlatform info
    let workstation_list = 
        DeviceInfo
        | where Timestamp > ago(lookback)
        | where OSPlatform == "Windows10"
        | summarize make_set(DeviceName)
        ;
    // 3. Generate the logon baseline for each account separately
    //    Baseline: devices(source and target) that the account logged on before
    let baseline_data = 
        IdentityLogonEvents
        | where Timestamp between (ago(30d) .. ago(1d))
        | where Application == "Active Directory"
        | where ActionType == "LogonSuccess"
        // Service account condition
        | where AccountName contains "srvc" or AccountName endswith "-admin"
        | where isnotempty(TargetDeviceName) and isnotempty(AccountName)
        | summarize SourceDevices=make_set(DeviceName),TargetDevices=make_set(TargetDeviceName) by AccountName
        ;
    // Get Service account logons of last 1 day(assume all of them are suspicious) and enrich the results with account baseline info
    let SuspiciousLogons = materialize  (
        IdentityLogonEvents
        | where Timestamp > ago(timeframe)
        | where Application == "Active Directory"
        | where ActionType == "LogonSuccess"
        // Service account condition
        | where AccountName contains "srvc" or AccountName endswith "-admin"
        | where isnotempty(TargetDeviceName) and isnotempty(AccountName)
        | summarize arg_max(Timestamp, *) by DeviceName, TargetDeviceName, AccountName // Get only the last logon
        // Enrich unusual logons with the baseline information and the building blocks
        | join kind=leftouter baseline_data on AccountName
        | extend IsSourceUsedBefore = iff(SourceDevices has DeviceName, 'Yes', 'No'), IsTargetUsedBefore = iff(TargetDevices has TargetDeviceName , 'Yes', 'No'),
                SourceDeviceType = case(DeviceName in~ (workstation_list),'Workstation',DeviceName in~ (server_list), 'Server', 'Unknown'), 
                TargetDeviceType = case(TargetDeviceName in~ (workstation_list),'Workstation',TargetDeviceName in~ (server_list), 'Server', 'Unknown'),
                AccountSourceCount=array_length(SourceDevices), 
                AccountTargetCount=array_length(TargetDevices)
        | project-away SourceDevices, TargetDevices
        )
        ;
    // Get all alerts of the Source/Target devices and accounts
    let SourceDeviceList = SuspiciousLogons | summarize make_set(DeviceName);
    let TargetDeviceList = SuspiciousLogons | summarize make_set(TargetDeviceName);
    let ServiceAccountList = SuspiciousLogons | summarize make_set(AccountName);
    // Account alerts
    let AccountAlerts = materialize 
        (
        AlertInfo
        | where Timestamp > ago(2d)
        | where not (Title has_any(whitelisted_alerts))
        | join kind=inner 
            (
            AlertEvidence 
            | where Timestamp > ago(2d)
            | where isnotempty(AccountName)
            ) on AlertId
        | where AccountName in (ServiceAccountList)
        | project AccountName, AlertId,Title, Severity
        | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
        | summarize Alerts=make_set(AlertDetails) by AccountName
        | extend All=pack(AccountName,Alerts)
        | summarize make_bag(All)
        )
        ;
    // Define function for getting all the alerts of a given entity(account)
    let GetAccountAlerts = (entity:string) {
        toscalar(AccountAlerts)[entity]
    };
    // Device Alerts
    let DeviceAlerts = materialize 
        (
        AlertInfo
        | where Timestamp > ago(2d)
        | where not (Title has_any(whitelisted_alerts))
        | join kind=inner 
            (
            AlertEvidence 
            | where Timestamp > ago(2d)
            | where isnotempty(DeviceName)
            ) on AlertId
        | where DeviceName in (SourceDeviceList) or DeviceName in (TargetDeviceList)
        | project DeviceName, AlertId,Title, Severity
        | extend AlertDetails=pack('AlertId', AlertId, 'Title', Title, 'Severity', Severity)
        | summarize Alerts=make_set(AlertDetails) by DeviceName
        | extend All=pack(DeviceName,Alerts)
        | summarize make_bag(All)
        )
        ;
    // Define function for getting all the alerts of a given entity(device)
    let GetDeviceAlerts = (entity:string) {
        toscalar(DeviceAlerts)[entity]
    };
    // Get any alert info related to the Source, Target or the Service account and enrich the results. 
    SuspiciousLogons 
    | extend SourceDeviceAlerts = GetDeviceAlerts(DeviceName), TargetDeviceAlerts = GetDeviceAlerts(TargetDeviceName), ServiceAccountAlerts = GetAccountAlerts(AccountName)
    // Display the most important results. 
    | where isnotempty(ServiceAccountAlerts) or isnotempty(SourceDeviceAlerts) or isnotempty(TargetDeviceAlerts) or (IsSourceUsedBefore == "No" and ShowResultsWithNoAlerts == "YES")
    // specific filter out conditions
    | project-reorder Timestamp, DeviceName, SourceDeviceType, AccountName, TargetDeviceName, TargetDeviceType, IsSourceUsedBefore, IsTargetUsedBefore, AccountSourceCount, AccountTargetCount, SourceDeviceAlerts, TargetDeviceAlerts, ServiceAccountAlerts
    ```
    #### References
     - https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Lateral%20Movement/TA0008%20-%20Potential%20Lateral%20Movement%20with%20Non-Personal%20Privileged%20Account.md

**I. Collection:**
- **Detection Rule:**
T1039 - Data from Network Shared Drive

    **KQL:** 
    ```
    let timeframe={{ timeframe | default('1h') }};
    let system_roles = datatable(role:string, system:string)                  // Link roles to systems
      [{{ role_system_mapping | default('"DC","dc1.corp.local",
      "DC","dc2.corp.local",
      "PRINT","printer.corp.local') }}
      ];
    let share_roles = datatable(role:string, share:string)                    // Link roles to shares
      [{{ role_share_mapping |  default('"DC", @"\\\\*\\sysvol",
      "DC",@"\\\\*\\netlogon",
      "PRINT",@"\\\\*\\print$"') }}];
    let allowed_system_shares = system_roles                                  // Link systems to shares
      | join kind=inner share_roles on role
      | extend system = tolower(system), share = tolower(share)
      | project-away role
      | summarize allowed_shares = make_set(share) by system;
    let monitored_principals=datatable(identifier:string, Group_Name:string)  // Define a data-table with groups to monitor
      [{{ monitored_principals | default('"AN", "Anonymous Logon",                                               // We accept the \'alias\' for these well-known SIDS
      "AU", "Authenticated Users",
      "BG","Built-in guests",
      "BU","Built-in users",
      "DG","Domain guests",
      "DU","Domain users",
      "WD","Everyone",
      "IU","Interactively Logged-on users",
      "LG","Local Guest",
      "NU","Network logon users",
      "513", "Domain Users",                                                  // Support matching on the last part of a SID
      "514", "Domain Guests",
      "545", "Builtin Users",
      "546", "Builtin Guests",
      "S-1-5-7", "Anonymous Logon" // For the global SIDS, we accept them as-is') }}
      ];
    SecurityEvent
    | where TimeGenerated >= ago(timeframe)
    | where EventID == 5143
    {{ pre_filter_1 }}
    | extend EventXML = parse_xml(EventData)
    | extend OldSD = tostring(EventXML["EventData"]["Data"][13]["#text"])     // Grab the previous Security Descriptor
    | extend NewSD = tostring(EventXML["EventData"]["Data"][14]["#text"])     // Grab the new Security Descriptor
    | project-away EventXML
    | where tostring(OldSD) !~ tostring(NewSD)                                // Don't bother with unchagned permissions
    | extend system = tolower(Computer), share=tolower(ShareName)             // Normalize system & sharename for matching with whitelist
    | join kind=leftouter allowed_system_shares on system                     // Retrieve the allowed shares per system
    | where not(set_has_element(allowed_shares, share))                       // Check if the current share is an allowed share
    | project-away system, share, allowed_shares                              // Get rid of temporary fields
    | extend DACLS = extract_all(@"(D:(?:\((?:[\w\-]*;){5}(?:[\w\-]*)\))*)", tostring(NewSD)) //Grab all isntances of D:(DACL), in case there are multiple sets.
    | project-away OldSD, NewSD                                               // Get rid of data we no longer need
    | mv-expand DACLS to typeof(string)                                       // In case there are any duplicate/subsequent D: entrys (e.g. D:<dacls>S:<sacls>D:<dacls>) split them out to individual D: sets
    | extend DACLS = substring(DACLS,2)                                       // Strip the leading D:
    | extend DACLS = split(DACLS, ")")                                        // Split the sets of DACLS ()() to an array of individual DACLS (), this removes the trailing ) character
    | mv-expand DACLS to typeof(string)                                       // Duplicate the records in such a way that only 1 dacl per record exist, we will aggregate them back later
    | extend DACLS = substring(DACLS, 1)                                      // Also remove the leading ( character
    | where not(isempty(DACLS)) and DACLS startswith "A;"                     // Remove any empty or non-allow DACLs
    | extend allowed_principal = tostring(split(DACLS,";",5)[0])              // Grab the SID what is affected by this DACL
    | extend allowed_principal = iff(not(allowed_principal startswith "S-" and string_size(allowed_principal) > 15), allowed_principal, split(allowed_principal,"-",countof(allowed_principal,"-"))[0]) //This line takes only the last part (e.g. 513) of a long SID, so you can refer to groups/users without needing to supply the full SID above.
    | join kind=inner monitored_principals on $left.allowed_principal == $right.identifier //Join the found groups to the table of groups to be monitored above, adds the more readable 'group_name)
    | project-away allowed_principal, identifier, DACLS
    | summarize Authorized_Public_Principals = make_set(Group_Name), take_any(*) by TimeGenerated, SourceComputerId, EventData //Summarize the fields back, making a set of the various group_name values for this record
    | project-away Group_Name
    {{ post_filter_1 }}
    ```
     #### References
     - https://github.com/FalconForceTeam/FalconFriday/blob/master/Collection/0xFF-0219-Excessive_Share_Permissions.md 
    
**I. Command and Control:**
- **Detection Rule:**
T1071.001 - Beacon Traffic Based on Common User Agents Visiting Limited Number of Domains.

    **KQL:** 
    ```
    let timeframe = 1d; // timeframe during which to search for beaconing behaviour
    let lookback = 7d; // Look back period to find if browser was used for other domains by user
    let min_requests=50; // Minimum number of requests to consider it beacon traffic
    let min_hours=8; // Minimum number of different hours during which connections were made to consider it beacon traffic
    let trusted_user_count=10; // If visited by this many users a domain is considered 'trusted'
    let max_sites=3; // Maximum number of different sites visited using this user-agent
    // Client specific Query to obtain 'browser like' traffic from Proxy logs
    let BrowserTraffic = (p:timespan) {
    CommonSecurityLog
    | where DeviceVendor == "Zscaler" and DeviceProduct == "NSSWeblog"
    | where TimeGenerated >ago(p)
    | project TimeGenerated, SourceUserName, DestinationHostName, RequestClientApplication
    | where (RequestClientApplication startswith "Mozilla/" and RequestClientApplication contains "Gecko")
    };
    let CommonDomains = BrowserTraffic(timeframe)
    | summarize source_count=dcount(SourceUserName) by DestinationHostName
    | where source_count>trusted_user_count
    | project DestinationHostName;
    let CommonUA = BrowserTraffic(timeframe)
    | summarize source_count=dcount(SourceUserName), host_count=dcount(DestinationHostName) by RequestClientApplication
    | where source_count>trusted_user_count and host_count > 100 // Normal browsers are browsers used by many people and visiting many different sites
    | project RequestClientApplication;
    // Find browsers that are common, i.e. many users use them and they use them to visit many different sites
    // But some users only use the browser to visit a very limited set of sites
    // These are considered suspicious - since they might be an attacker masquerading a beacon as a legitimate browser
    let SuspiciousBrowers = BrowserTraffic(timeframe)
    | where RequestClientApplication in(CommonUA)
    | summarize BrowserHosts=make_set(DestinationHostName),request_count=count() by RequestClientApplication, SourceUserName
    | where array_length(BrowserHosts) <= max_sites and request_count >= min_requests
    | project RequestClientApplication, SourceUserName,BrowserHosts;
    // Just reporting on suspicious browsers gives too many false positives
    // For example users that have the browser open on the login screen of 1 specific application
    // In the suspicious browsers we can search for 'Beacon like' behaviour
    // Get all browser traffic by the suspicious browsers
    let PotentialAlerts=SuspiciousBrowers
    | join BrowserTraffic(timeframe) on RequestClientApplication, SourceUserName
    // Find beaconing like traffic - i.e. contacting the same host in many different hours
    | summarize hour_count=dcount(bin(TimeGenerated,1h)), BrowserHosts=any(BrowserHosts), request_count=count() by RequestClientApplication, SourceUserName, DestinationHostName
    | where hour_count >= min_hours and request_count >= min_requests
    // Remove common domains like login.microsoft.com
    | join kind=leftanti CommonDomains on DestinationHostName
    | summarize RareHosts=make_set(DestinationHostName), TotalRequestCount=sum(request_count), BrowserHosts=any(BrowserHosts) by RequestClientApplication, SourceUserName
    // Remove browsers that visit any common domains
    | where array_length(RareHosts) == array_length(BrowserHosts);
    // Look back for 7 days to see the browser was not used to visit more hosts
    // This is to get rid of someone that started up the browser a long time ago
    // And left only a single tab open
    PotentialAlerts
    | join BrowserTraffic(lookback) on SourceUserName, RequestClientApplication
    | summarize RareHosts=any(RareHosts),BrowserHosts1d=any(BrowserHosts),BrowserHostsLookback=make_set(DestinationHostName) by SourceUserName, RequestClientApplication
    | where array_length(RareHosts) == array_length(BrowserHostsLookback)
    ```
     #### References
     - https://github.com/FalconForceTeam/FalconFriday/blob/master/Command%20and%20Control/T1071.001.md

    T1105 - Ingress Tool Transfer - Certutil.

    **KQL:** 
    ```
    // set the time span for the query
    let Timeframe = 30d;
    // set the HashTimeframe for the hash lookup, longer makes more accurate but obviously also more resource intensive
    let HashTimeframe = 30d;
    // Get all known SHA1 hashes for certutil executions or renamed files formerly named certutil
    let CertUtilPESha1=DeviceProcessEvents | where Timestamp > ago(HashTimeframe)| where FileName contains "certutil"  | where isnotempty(SHA1) | summarize sha1=make_set(SHA1);
    let CertUtilFESha1=DeviceFileEvents | where Timestamp > ago(HashTimeframe)| where PreviousFileName contains "certutil" or FileName contains "certutil"  | where isnotempty(SHA1) | summarize sha1=make_set(SHA1);
    DeviceProcessEvents
    | where Timestamp > ago(Timeframe)
    // get all executions by processes with a SHA1 hash that is or was named certutil
    | where SHA1 in (CertUtilPESha1) or SHA1 in (CertUtilFESha1) or FileName =~ "certutil.exe" or ProcessCommandLine has_any ("certutil")
    // create a new field called CleanProcessCommandLine which gets populated with the value of ProcessCommandLine as Windows parses it for execution, 
    // removing any potential command line obfuscation 
    | extend CleanProcessCommandLine=parse_command_line(ProcessCommandLine, "windows")
    // search for de-obfuscated commands used 
    | where CleanProcessCommandLine has_any ("decode", "encode", "verify","url") 
    // urlcache is the documented attribute, only url is also accepted
    // verifyctl is the documented attribute, only verify is also accepted
    | order by Timestamp
    | project Timestamp, CleanProcessCommandLine, ProcessCommandLine, SHA1
    ```
    #### References
     - https://github.com/FalconForceTeam/FalconFriday/blob/master/Command%20and%20Control/T1105-WIN-001.md
    
**I. Exfiltration:**
- **Detection Rule:**
T1567 - Exfiltration Over Web Service - Linked Malicious Storage Artifacts.

    **KQL:** 
    ```
    //Collect the alert events
    let alertData = SecurityAlert
    | where DisplayName has "Potential malware uploaded to"
    | extend Entities = parse_json(Entities)
    | mv-expand Entities;
    //Parse the IP address data
    let ipData = alertData
    | where Entities['Type'] =~ "ip"
    | extend AttackerIP = tostring(Entities['Address']), AttackerCountry = tostring(Entities['Location']['CountryName']);
    //Parse the file data
    let FileData = alertData
    | where Entities['Type'] =~ "file"
    | extend MaliciousFileDirectory = tostring(Entities['Directory']), MaliciousFileName = tostring(Entities['Name']), MaliciousFileHashes = tostring(Entities['FileHashes']);
    //Combine the File and IP data together
    ipData
    | join (FileData) on VendorOriginalId
    | summarize by TimeGenerated, AttackerIP, AttackerCountry, DisplayName, ResourceId, AlertType, MaliciousFileDirectory, MaliciousFileName, MaliciousFileHashes
    //Create a type column so we can track if it was a File storage or blobl storage upload
    | extend type = iff(DisplayName has "file", "File", "Blob")
    | join (
      union
      StorageFileLogs,
      StorageBlobLogs
      //File upload operations
      | where OperationName =~ "PutBlob" or OperationName =~ "PutRange"
      //Parse out the uploader IP
      | extend ClientIP = tostring(split(CallerIpAddress, ":", 0)[0])
      //Extract the filename from the Uri
      | extend FileName = extract(@"\/([\w\-. ]+)\?", 1, Uri)
      //Base64 decode the MD5 filehash, we will encounter non-ascii hex so string operations don't work
      //We can work around this by making it an array then converting it to hex from an int
      | extend base64Char = base64_decode_toarray(ResponseMd5)
      | mv-expand base64Char
      | extend hexChar = tohex(toint(base64Char))
      | extend hexChar = iff(strlen(hexChar) < 2, strcat("0", hexChar), hexChar)
      | extend SourceTable = iff(OperationName has "range", "StorageFileLogs", "StorageBlobLogs")
      | summarize make_list(hexChar, 1000) by CorrelationId, ResponseMd5, FileName, AccountName, TimeGenerated, RequestBodySize, ClientIP, SourceTable
      | extend Md5Hash = strcat_array(list_hexChar, "")
      //Pack the file information the summarise into a ClientIP row
      | extend p = pack("FileName", FileName, "FileSize", RequestBodySize, "Md5Hash", Md5Hash, "Time", TimeGenerated, "SourceTable", SourceTable)
      | summarize UploadedFileInfo=make_list(p, 10000), FilesUploaded=count() by ClientIP
          | join kind=leftouter (
            union
            StorageFileLogs,
            StorageBlobLogs
            | where OperationName =~ "DeleteFile" or OperationName =~ "DeleteBlob"
            | extend ClientIP = tostring(split(CallerIpAddress, ":", 0)[0])
            | extend FileName = extract(@"\/([\w\-. ]+)\?", 1, Uri)
            | extend SourceTable = iff(OperationName has "range", "StorageFileLogs", "StorageBlobLogs")
            | extend p = pack("FileName", FileName, "Time", TimeGenerated, "SourceTable", SourceTable)
            | summarize DeletedFileInfo=make_list(p, 10000), FilesDeleted=count() by ClientIP
            ) on ClientIP
      ) on $left.AttackerIP == $right.ClientIP
    | mvexpand UploadedFileInfo
    | extend LinkedMaliciousFileName = tostring(UploadedFileInfo.FileName)
    | extend LinkedMaliciousFileHash = tostring(UploadedFileInfo.Md5Hash)
    | extend HashAlgorithm = "MD5"
    | project AlertTimeGenerated = TimeGenerated, LinkedMaliciousFileName, LinkedMaliciousFileHash, HashAlgorithm, AlertType, AttackerIP, AttackerCountry, MaliciousFileDirectory, MaliciousFileName, FilesUploaded, UploadedFileInfo
    ```
    T1567 - Exfiltration Over Web Service - Insider Risk_Sensitive Data Access Outside Organizational Geo-location.

    **KQL:** 
    ```
    InformationProtectionLogs_CL
    | extend UserPrincipalName = UserId_s
    | where LabelName_s <> ""
    | join kind=inner (SigninLogs) on UserPrincipalName
    | extend City = tostring(LocationDetails.city)
    // | where City <> "New York" // Configure Location Details within Organizational Requirements
    | extend State = tostring(LocationDetails.state)
    // | where State <> "Texas" // Configure Location Details within Organizational Requirements
    | extend Country_Region = tostring(LocationDetails.countryOrRegion)
    // | where Country_Region <> "US" // Configure Location Details within Organizational Requirements
    // | lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey
    | summarize count() by UserPrincipalName, LabelName_s, Activity_s, City, State, Country_Region, TimeGenerated
    | sort by count_ desc
    | limit 25
    | extend AccountCustomEntity = UserPrincipalName
    ```
    #### References
     - https://github.com/Azure/Azure-Sentinel/
