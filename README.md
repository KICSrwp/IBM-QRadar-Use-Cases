# **QRadar Security Use Cases**

This document outlines several common security use cases for IBM QRadar, focusing on both real-time alerting via custom rules and historical investigation using Ariel Query Language (AQL).

## **1\. Windows Audit Log Tampering**

The primary way to implement this use case for real-time alerting in QRadar is by creating a custom rule that will generate an offense when these events are detected.

### **Creating a New Event Rule**

1. **Navigate to the Rules Section:**  
   * Click on the **Offenses** tab in the QRadar console.  
   * On the left-hand menu, click on **Rules**.  
2. **Create a New Event Rule:**  
   * In the "Rules" screen, click on the **Actions** dropdown menu and select **New Event Rule**.  
   * A Rule Wizard will appear. Click **Next** on the first page.  
3. **Define the Rule Conditions:**  
   * Give your rule a descriptive name, such as "Windows Audit Log Tampering Detected".  
   * In the "Rule Test Stack Editor," build the logic to detect the specific events. The most straightforward way is to look for the Windows Event IDs directly.  
   * The first condition should specify the Log Source Type. In the search box, type "log source type" and double-click the test "when the Log Source Type is one of the following".  
   * In the dialog that appears, add "Microsoft Windows Security Event Log" and click **Submit**.  
   * Next, add the conditions for the Event IDs. In the search box, type "event id" and double-click the test "and when the Event ID is one of the following".  
   * Enter **1102** and click **Add**.  
   * Enter **1100** and click **Add**.  
   * Enter **104** and click **Add**.  
   * Click **Submit**.  
4. **Configure the Rule Response:**  
   * Click **Next** to move to the "Rule Responses" page.  
   * Check the box for **"Ensure the detected event is part of an offense"**. This will cause QRadar to create an offense when the rule is triggered.  
   * You can set the **Severity** of the offense (e.g., a high severity of 8 or 9 is appropriate for potential tampering).  
   * It's also a good practice to select **"Dispatch New Event"** and provide a descriptive name for the new event, such as "AuditLogTamperingDetected". This makes it easier to search for these specific rule triggers later.  
5. **Review and Finish:**  
   * Click **Next** to see a summary of your rule.  
   * Verify that the conditions and responses are correct, and then click **Finish**.

Your rule is now active and will monitor all incoming Windows events. If an event with an ID of 1102, 1100, or 104 is detected, an offense will be generated, alerting your security team to the potential threat.

### **AQL Search for Investigation**

To replicate the stats count by portion of your Splunk query for historical analysis and investigation, you will use the **Ariel Query Language (AQL)** in the **Log Activity** tab.

1. **Navigate to the Log Activity Tab:**  
   * Click on the **Log Activity** tab in the QRadar console.  
2. Construct the AQL Query:  
   In the search bar, you will enter an AQL query. The following query is the QRadar equivalent of your Splunk search:
   ```
   SELECT QIDNAME(qid) as "Event Name", "Event ID", LOGSOURCENAME(logsourceid) as "Log Source", COUNT(\*) as "Count" FROM events WHERE devicetype \= 5 AND "Event ID" IN (1102, 1100, 104\) GROUP BY "Event ID", "Log Source" LAST 24 HOURS

   * SELECT QIDNAME(qid) as "Event Name", "Event ID", LOGSOURCENAME(logsourceid) as "Log Source", COUNT(\*) as "Count": This selects the columns you want to display, similar to the by clause in your Splunk query. We are also getting the count of events.  
   * FROM events: This specifies that you are searching the events database.  
   * WHERE devicetype \= 5 AND "Event ID" IN (1102, 1100, 104): This is the filter condition. devicetype \= 5 is a common identifier for "Microsoft Windows Security Event Log". We then specify the Event IDs we are interested in.  
   * GROUP BY "Event ID", "Log Source": This groups the results, similar to the stats command in Splunk.  
   * LAST 24 HOURS: This defines the time frame for the search. You can change this to any time frame you need. 
   
3. **Run the Search:**  
   * After entering the AQL query, click the **Search** button. The results will be displayed in a table, showing you a count of each of the targeted events, grouped by the event type and the log source (the Windows host).

## **2\. Finding Large Web Uploads**

This use case aims to detect potential data exfiltration by identifying unusually large file uploads going through a web proxy or firewall.

### **QRadar \- Real-Time Rule**

A real-time rule will create an offense the moment a large upload is detected.

1. **Navigate to Rules:** Go to the **Offenses** tab and select **Rules** from the side menu.  
2. **Create New Event Rule:** From the **Actions** dropdown, choose **New Event Rule**.  
3. **Apply Rule to Web Proxy Events:** In the rule wizard, start by filtering for your web proxy or firewall log sources.  
   * Apply the test: when the Log Source Type is one of the following  
   * Select the appropriate log source type (e.g., Blue Coat SG, Cisco IronPort, Palo Alto PA Series).  
4. **Set the Threshold Condition:** The key is to check the size of the outbound traffic. In QRadar, this is typically the **Transmitted Bytes** property.  
   * Apply the test: and when the property Transmitted Bytes is greater than  
   * Enter the value 35000000\.  
5. **Configure the Response:**  
   * On the next page, ensure **Dispatch New Event** and **Ensure the detected event is part of an offense** are checked.  
   * Set an appropriate Severity (e.g., 7\) and assign a descriptive name like "Potential Data Exfiltration: Large Web Upload".  
6. **Finish:** Review the summary and save the rule.

### **QRadar \- AQL Investigation Search**

Use this AQL query in the **Log Activity** tab to search for historical instances of large uploads.
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   "Source IP",  
   "Username",  
   "Destination IP",  
   "URL",  
   "Transmitted Bytes"  
FROM  
    events  
WHERE  
   "Transmitted Bytes" \> 35000000  
   AND  
LOGSOURCETYPENAME(devicetype) ILIKE '%Palo Alto PA Series%' \-- Or your specific firewall/proxy log source type  
LAST 24 HOURS
```
## **3\. Detecting Recurring Malware on a Host**

This use case identifies hosts where malware is repeatedly detected, suggesting that the initial remediation failed. The logic is to find the same malware on the same host multiple times within a specific timeframe.

### **QRadar \- Real-Time Rule**

This is a correlation rule that triggers on a pattern of events.

1. **Navigate to Rules:** Go to the **Offenses** tab and select **Rules**.  
2. **Create New Event Rule:** From **Actions**, choose **New Event Rule**.  
3. **Define the Pattern:**  
   * First, identify the initial malware event. Apply the test: and when the QID is one of the following and search for QIDs related to malware detection from your AV source (e.g., "Virus/Malware Detected", "Threat Found").  
   * Next, define the recurrence condition. Apply the test: and when an event with the same Threat Name and the same Source IP has been seen more than 1 times in 30 minutes.  
4. **Configure the Response:**  
   * On the rule response page, dispatch a new event with a name like "Recurring Malware Detected on Host".  
   * Ensure it contributes to an offense and set a high severity (e.g., 8), as this indicates a persistent infection.  
5. **Finish:** Save the rule.

### **QRadar \- AQL Investigation Search**

This query searches for hosts and malware names that have appeared more than once.
```
SELECT "Threat Name", "Source IP", UNIQUECOUNT("Source IP") as "Host Count", COUNT(\*) as "Detection Count", (MAX(startTime) \- MIN(startTime))/1000 as "TimeRange\_Seconds" FROM events WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%symantec%' \-- Or your specific AV Log Source Type GROUP BY "Threat Name", "Source IP" HAVING "Detection Count" \> 1 AND TimeRange\_Seconds \> 1800 LAST 7 DAYS
```
## **4\. Detecting Brute Force Attacks**

This use case identifies brute-force attempts by counting a high number of login failures from the same user or source within a short time.

### **QRadar \- Real-Time Rule (Built-in)**

QRadar has excellent, pre-built rules for this. It is highly recommended to enable and tune the existing rules.

1. **Navigate to Rules:** Go to the **Offenses** tab and select **Rules**.  
2. **Search for Existing Rules:** In the search bar, type "brute force".  
3. **Enable and Tune:** You will find rules like:  
   * Authentication: Multiple Login Failures from the Same Source  
   * Authentication: Login Failures Followed by a Success for the Same User  
   * Enable these rules. You can edit them to adjust the thresholds (e.g., 5 failures in 5 minutes).

### **QRadar \- AQL Investigation Search**

For Windows:
```
SELECT  
   "Username",  
   "Source IP",  
   LOGSOURCENAME(logsourceid) as "Host",  
   COUNT(\*) as "Failure Count"  
FROM  
    events  
WHERE  
   "Event ID" \= 4625 \-- Windows Logon Failure Event  
GROUP BY  
   "Username", "Source IP", "Host"  
HAVING  
   "Failure Count" \>= 5  
TIMESPAN 5 minutes  
LAST 24 HOURS
```
For Linux:
```
SELECT  
   "Username",  
   "Source IP",  
   LOGSOURCENAME(logsourceid) as "Host",  
   COUNT(\*) as "Failure Count"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) \= 'Linux OS'  
   AND  
QIDNAME(qid) ILIKE '%Failed Password%' \-- Or a more specific QID for failed logins  
GROUP BY  
   "Username", "Source IP", "Host"  
HAVING  
   "Failure Count" \>= 5  
TIMESPAN 5 minutes  
LAST 24 HOURS
```
## **5\. Detecting Unencrypted Web Communications**

This use case finds web traffic to specific applications that is not using the standard encrypted port (443), which could expose sensitive data.

### **QRadar \- Real-Time Rule**

1. **Navigate to Rules:** Go to the **Offenses** tab and select **Rules**.  
2. **Create New Event Rule:** From **Actions**, choose **New Event Rule**.  
3. **Define Conditions:**  
   * Apply the test: and when the Log Source Type is one of the following and select your firewall log source type.  
   * Apply the test: and when the property Application is one of the following and enter Workday\*. Note: This requires that your firewall can identify the application.  
   * Apply the test: and when the property Destination Port is not 443\.  
4. **Configure the Response:**  
   * Dispatch a new event named "Unencrypted Workday Communication Detected".  
   * Create an offense to ensure this is investigated.  
5. **Finish:** Save the rule.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   "Username",  
   "Application",  
   "Source IP",  
   "Destination IP",  
   "Destination Port",  
   "Transmitted Bytes"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) \= 'Palo Alto PA Series' \-- Or your firewall LS type  
   AND  
"Application" ILIKE 'workday%'  
   AND  
"Destination Port" \!= 443  
LAST 24 HOURS
```
## **6\. Identifying Web Users By Country**

This is a reporting and visualization use case. QRadar automatically enriches IP addresses with geographic data, making this straightforward.

### **QRadar \- Real-Time Rule**

A real-time rule is not typical for this scenario. However, you could create a rule to alert on traffic from a specific country of interest (e.g., from a sanctioned country).

### **QRadar \- AQL Investigation Search**

This query provides the data needed for a report or a dashboard widget.

SELECT  
   "Source Country",  
   UNIQUECOUNT("Source IP") as "Unique\_IP\_Count"  
FROM  
    events  
WHERE  
   QIDNAME(qid) ILIKE '%web%access%' \-- Filter for web server logs  
GROUP BY  
   "Source Country"  
ORDER BY  
   "Unique\_IP\_Count" DESC  
LAST 24 HOURS

**Visualization:** You can take this AQL query and use it to build a table or a map chart in the **QRadar Pulse** dashboard tab.
