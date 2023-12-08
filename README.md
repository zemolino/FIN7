# Analysis of FIN7 TTPs:
FIN7 is a sophisticated threat actor known for financially motivated attacks against organizations. Their TTPs include a variety of techniques across different stages of the attack lifecycle. Let's focus on a few key techniques and propose enhancements for detection:

**A. Spearphishing:**
* FIN7 often utilizes spearphishing emails with malicious attachments or links to deliver malware.
* They use social engineering to craft convincing emails.

**B. Execution:**
* FIN7 leverages PowerShell for various tasks, such as downloading payloads and executing commands.

**C. Credential Dumping:**
* The threat actor extracts credentials from compromised systems to escalate privileges or move laterally.

**D. Registry Run Keys / Startup Folder:**
* FIN7 persists by adding malicious entries in the Registry Run keys or Startup folder.

**E. User Account Control (UAC) Bypass:**
*  FIN7 attempts to bypass UAC to execute elevated commands without user consent.

**F. PowerShell Profile:**
* The group modifies PowerShell profiles to establish persistence and execute malicious actions.

**G. File Deletion:**
* FIN7 deletes files to hinder forensic analysis and cover their tracks.
	
**H. Data Encrypted:**
* The threat actor encrypts data to extort victims and demands ransom payments.

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
Command and Scripting Interpreter
