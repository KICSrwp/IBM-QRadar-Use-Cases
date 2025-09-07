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
	```
   * SELECT QIDNAME(qid) as "Event Name", "Event ID", LOGSOURCENAME(logsourceid) as "Log Source", COUNT(\*) as "Count": This selects the columns you want to display, similar to the by clause in your Splunk query. We are also getting the count of events.  
   * FROM events: This specifies that you are searching the events database.  
   * WHERE devicetype \= 5 AND "Event ID" IN (1102, 1100, 104\): This is the filter condition. devicetype \= 5 is a common identifier for "Microsoft Windows Security Event Log". We then specify the Event IDs we are interested in.  
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
   * Enter the value 35000000.  
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

For Linux:

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
   * Apply the test: and when the property Destination Port is not 443.  
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
```
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
```
**Visualization:** You can take this AQL query and use it to build a table or a map chart in the **QRadar Pulse** dashboard tab.

## **7\. Identifying Slow Web Content**

This use case helps find web pages with high response times. This requires that "response time" is parsed from the web server logs. If it's not a default property, you will first need to create a **Custom Event Property** to extract it.

### **QRadar \- Real-Time Rule**

* **Prerequisite:** Create a numeric Custom Event Property (CEP) named ResponseTime to extract the response time from your web server logs.  
* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Log Source Type is one of the following (e.g., Apache HTTP Server, Microsoft IIS).  
  * Apply the test: and when the property ResponseTime is greater than 5000 (for a 5-second threshold, in milliseconds).  
* **Configure the Response:** Dispatch a new event and create a low-severity offense to track poorly performing pages.

### **QRadar \- AQL Investigation Search**

This query assumes you have a numeric Custom Event Property named ResponseTime.
```
SELECT  
   "URL" as "URI\_Path",  
   AVG(ResponseTime) as "Average\_Response\_Time"  
FROM  
    events  
WHERE  
    "Log Source Type" IN ('Apache HTTP Server', 'Microsoft IIS')  
    AND "URL" IS NOT NULL  
GROUP BY  
   "URI\_Path"  
ORDER BY  
   "Average\_Response\_Time" DESC  
LAST 24 HOURS
```
## **8\. Finding New Local Admin Accounts**

This crucial use case detects when a new user is created and quickly added to a privileged group like Administrators, a common attacker technique.

### **QRadar \- Real-Time Rule**

This requires a rule that looks for a sequence of events.

* Navigate to Rules: Go to the **Offenses** tab and select **Rules**.  
* Create New Event Rule: From **Actions**, choose **New Event Rule**.  
* **Define the Sequence:**  
  * Apply the test: and when the Event ID is 4720 (A user account was created).  
  * Apply the test: and followed by an event where the Event ID is 4732 (A member was added to a security-enabled local group).  
  * Specify the timeframe: within 180 minutes.  
  * Link the events: Ensure both events have the **same Username**.  
* **Filter for Admin Group:**  
  * Add a rule test specifically for the second event: and when the event matches this search filter. In the filter box, enter Group Name \= 'Administrators'.  
* **Configure the Response:** Dispatch a new event named "New Local Admin Account Created" and create a high-severity offense.

### **QRadar \- AQL Investigation Search**

AQL is not as powerful as Splunk's transaction command for this. The best approach is to search for the offense generated by the rule above. However, you can find the individual events with this query:
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   QIDNAME(qid) as "Action",  
   "Username",  
   "Group Name"  
FROM  
    events  
WHERE  
    "Event ID" IN (4720, 4732\)  
    AND ("Group Name" \= 'Administrators' OR "Group Name" IS NULL)  
ORDER BY  
   "Username", startTime ASC  
LAST 24 HOURS
```
## **9\. Finding Interactive Logins from Service Accounts**

This use case detects when a service account, which should only be used by applications, is used for an interactive logon—a strong indicator of misuse or compromise.

### **QRadar \- Real-Time Rule**

* **Prerequisite:** It's best to maintain a **Reference Set** named Service Accounts that contains the usernames of all your service accounts.  
* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Username is contained in any of the following Reference Sets. Select the Service Accounts reference set.  
  * Alternatively, for pattern-based names, use: and when the property Username matches the following regular expression: (?i)svc\_.\*  
  * Apply the test: and when the property Logon Type is one of the following. Add the value 2 (for Interactive Logon).  
* **Configure the Response:** Dispatch a new event named "Interactive Logon from Service Account" and create a high-severity offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Login Time",  
   "Username",  
   "Source IP",  
   "Destination IP" as "Destination Host"  
FROM  
    events  
WHERE  
    "Logon Type" \= '2'  
    AND ("Username" ILIKE 'svc\_%' OR "Username" ILIKE '%\_svc') \-- Adjust regex for your naming convention  
LAST 24 HOURS
```
## **10\. Log Volume Trending**

This is a visualization and reporting use case designed to monitor the health and activity of applications by graphing the volume of logs over time.

### **QRadar \- Real-Time Rule**

A real-time rule is not suitable for this use case, as it's about monitoring trends, not detecting a specific threat. However, you could create a rule to detect an **anomaly** in log volume (e.g., if the volume suddenly drops to zero or spikes unexpectedly), which would involve more advanced anomaly detection rules in QRadar.

### **QRadar \- AQL for Dashboards and Reports**

The best way to replicate this is with an AQL query that powers a dashboard chart in the **QRadar Pulse** tab.

* Navigate to QRadar Pulse: Go to the dashboard tab.  
* Add a New Dashboard Item: Choose "Chart" and then "Time Series".  
* Use the Following AQL Query:
```
SELECT  
   LOGSOURCENAME(logsourceid) as "Host",  
   COUNT(\*) as "Event Count"  
FROM  
    events  
WHERE  
    \-- Filter for your specific application log sources  
   LOGSOURCEGROUPNAME(logsourcegroupid) \= 'Application Servers' \-- Or use LOGSOURCENAME() or other filters  
GROUP BY  
   "Host", STARTTIME  
TIMESPAN 1h \-- Sets the overall time window for the chart
```
* **How it Works:** This query counts all events, groups them by the log source (host), and plots them over time using the **STARTTIME** function within the time series chart. The QRadar dashboard will handle the visualization, creating a line chart similar to Splunk's timechart.

## **11\. Basic TOR Traffic Detection**

This use case identifies traffic associated with The Onion Router (TOR) network, which is often used to anonymize activity. This relies on your firewall being able to identify TOR as an application.

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Log Source Type is one of the following and select your firewall log source type (e.g., Palo Alto PA Series, Fortinet FortiGate).  
  * Apply the test: and when the property Application is one of the following. Enter Tor. (Note: The application name must match what your firewall provides).  
* **Configure the Response:**  
  * Dispatch a new event named "TOR Traffic Detected".  
  * Create an offense. This could be a medium severity (e.g., 6), as TOR has legitimate uses, but is also frequently used for malicious activity.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   "Source IP",  
   "Source Port",  
   "Destination IP",  
   "Destination Port",  
   "Application",  
   "Transmitted Bytes"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) ILIKE '%firewall%' \-- General filter for firewall logs  
   AND "Application" \= 'Tor'  
LAST 24 HOURS
```
## **12\. & 13\. Measuring Storage I/O Latency & Speed**

These use cases monitor server performance by analyzing iostat logs for I/O latency and operations per second.

* **Prerequisite:** You must be collecting iostat logs into QRadar. You will also need to create **Custom Event Properties (CEPs)** to parse the values for latency and total\_ops from the raw log payload, as these are not standard QRadar properties. Let's assume you've created numeric CEPs named IOLatency and TotalIO\_Ops.

### **QRadar \- Real-Time Rule (for High Latency)**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Log Source Type is one of the following and select your iostat log source type.  
  * Apply the test: and when the custom property IOLatency is greater than a specific threshold (e.g., 100 milliseconds).  
* **Configure the Response:** Dispatch a new event for "High I/O Latency Detected" to create a low-severity offense for tracking performance issues.

### **QRadar \- AQL for Dashboards (Latency & Speed)**

These queries can be used in **QRadar Pulse** to create time series charts.
```
SELECT  
   LOGSOURCENAME(logsourceid) as "Host",  
   AVG(IOLatency) as "Average\_Latency"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) \= 'iostat' \-- Or your specific log source type  
GROUP BY  
   "Host", STARTTIME  
LAST 24 HOURS
```
**I/O Utilization by Host and Device (\#13):**
```
SELECT  
   CONCAT(LOGSOURCENAME(logsourceid), ':', Device) as "HostDevice",  
   AVG(TotalIO\_Ops) as "Average\_Total\_Ops"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) \= 'iostat' \-- Or your specific log source type  
   AND "Device" IS NOT NULL \-- Assumes a CEP named 'Device' is also parsed  
GROUP BY  
   "HostDevice", STARTTIME  
LAST 24 HOURS
```
## **14\. Measuring Memory Utilization by Host**

This use case alerts when a host's memory usage exceeds a critical threshold.

* **Prerequisite:** You must collect vmstat (or similar) logs and create a numeric **Custom Event Property (CEP)** named MemoryUsedPercent to parse the memory utilization percentage.

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Log Source Type is one of the following and select your vmstat log source type.  
  * Apply the test: and when the custom property MemoryUsedPercent is greater than 80.  
* **Configure the Response:** Dispatch a new event for "High Memory Utilization Detected" and create a low-severity offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   LOGSOURCENAME(logsourceid) as "Host",  
   MAX(MemoryUsedPercent) as "Max\_Memory\_Used\_Percent"  
FROM  
    events  
WHERE  
   LOGSOURCETYPENAME(devicetype) \= 'vmstat' \-- Or your specific log source type  
GROUP BY  
   "Host"  
HAVING  
   "Max\_Memory\_Used\_Percent" \> 80  
LAST 24 HOURS
```
## **15\. Rogue DNS Detection**

This critical use case identifies internal clients that are bypassing your approved DNS servers, which can be a sign of malware or misconfiguration.

* **Prerequisite:** Create a **Reference Set** named "Authorized DNS Servers" and populate it with the IP addresses of your official internal DNS servers (e.g., 192.168.14.10).

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Destination Port is 53.  
  * Apply the test: and when the protocol is one of the following: udp, tcp.  
  * Apply the test: and when the Destination IP is NOT contained in any of the following Reference Sets. Select your Authorized DNS Servers reference set.  
  * Apply the test: and when the Source IP is part of any of the following networks. Select your internal IP space (e.g., 192.168.0.0/16).  
* **Configure the Response:** Dispatch a new event for "Rogue DNS Traffic Detected" and create a medium-severity offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   "Source IP",  
   UNIQUECOUNT("Destination IP") as "Unique\_DNS\_Server\_Count",  
   LIST("Destination IP", 5\) as "Queried\_DNS\_Servers"  
FROM  
    events  
WHERE  
   "Destination Port" \= 53  
   AND NOT CIDR\_MATCH('192.168.14.10/32', "Destination IP") \-- Hardcoded example; Reference Set is better for rules  
   AND CIDR\_MATCH('192.168.0.0/16', "Source IP")  
   AND CIDR\_MATCH('192.168.0.0/16', "Destination IP") \-- Matches your original Splunk logic  
GROUP BY  
   "Source IP"  
LAST 24 HOURS
```
## **Endpoint Detection Use Cases (16-29)**

The following use cases all rely on detailed endpoint logs, such as Windows PowerShell Logging, Windows Security Event Logs, or a Sysmon/EDR solution.  
The key is mapping the Splunk fields (ScriptBlockText, Processes.process, Processes.process\_name) to QRadar's normalized properties, which are typically Payload, Command Line, and Process Name.

### **Real-Time Rule Pattern:**

* Create a **New Event Rule**.  
* Apply test: and when the Log Source Type is Microsoft Windows Security Event Log (for Sysmon).  
* Apply test: and when the property Process Name is '... .exe'.  
* Apply test: and when the property Command Line contains '... ...'.  
* Configure a high-severity offense.

### **AQL Search Pattern:**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   "Username",  
   "Process Name",  
   "Command Line"  
FROM  
    events  
WHERE  
   "Process Name" \= '... .exe'  
   AND "Command Line" ILIKE '%...%'  
LAST 7 DAYS
```
### **Applying this pattern:**

* **21\. Attempt To Add Certificate To Untrusted Store:**  
  * Process Name: certutil.exe  
  * Command Line: ILIKE %-addstore%  
* **22\. Batch File Write to System32:** (This is a file write, not a process)  
  * Rule Test: and when the QID is (find QID for "File Created").  
  * Rule Test: and when the property File Path contains '\\Windows\\System32\\'.  
  * Rule Test: and when the property File Name ends with '.bat'.  
* **23\. BCDEdit Failure Recovery Modification:**  
  * Process Name: bcdedit.exe  
  * Command Line: ILIKE %recoveryenabled%no%  
* **24\. BITS Job Persistence:**  
  * Process Name: bitsadmin.exe  
  * Command Line: (regex matching create OR addfile OR resume, etc.)  
* **25\. BITSAdmin Download File:**  
  * Process Name: bitsadmin.exe  
  * Command Line: ILIKE %transfer%  
* **26\. CertUtil Download With URLCache and Split:**  
  * Process Name: certutil.exe  
  * Command Line: ILIKE %urlcache% AND ILIKE %split%  
* **27\. CertUtil Download With VerifyCtl and Split:**  
  * Process Name: certutil.exe  
  * Command Line: ILIKE %verifyctl% AND ILIKE %split%  
* **28\. Certutil exe certificate extraction:**  
  * Process Name: certutil.exe  
  * Command Line: ILIKE %-exportPFX%  
* **29\. CertUtil With Decode Argument:**  
  * Process Name: certutil.exe  
  * Command Line: ILIKE %decode%

## **30\. Create Local Admin Accounts Using net.exe**

This use case detects the common administrative tool net.exe being used to create users or add them to the local administrators group.

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the property Process Name is one of the following: net.exe, net1.exe.  
  * Create a test group with an **OR** condition:  
    * Inside the group, add the test: and when the property Command Line contains 'localgroup'.  
    * Inside the group, add the test: and when the property Command Line contains '/add'.  
* **Configure the Response:** Dispatch a new event for "Local Admin Account Creation via net.exe" and create a high-severity (8) offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   LOGSOURCENAME(logsourceid) as "Host",  
   "Username",  
   "Process Name",  
   "Command Line"  
FROM  
    events  
WHERE  
   "Process Name" IN ('net.exe', 'net1.exe')  
   AND ("Command Line" ILIKE '%localgroup%' OR "Command Line" ILIKE '%/add%')  
LAST 7 DAYS
```
## **31\. Create Remote Thread into LSASS**

Detects a common credential dumping technique where a process injects a thread into the Local Security Authority Subsystem Service (LSASS). This requires Sysmon Event ID 8\.

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Event ID is 8 (Sysmon: CreateRemoteThread).  
  * Apply the test: and when the property Target Process Name is 'lsass.exe'.  
* **Configure the Response:** Dispatch a new event for "Remote Thread Injected into LSASS \- Possible Credential Dumping" and create a high-severity (10) offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   LOGSOURCENAME(logsourceid) as "Host",  
   "Process Name" as "Source Process",  
   "Target Process Name"  
FROM  
    events  
WHERE  
    "Event ID" \= 8 \-- Sysmon: CreateRemoteThread  
    AND "Target Process Name" \= 'lsass.exe'  
LAST 7 DAYS
```
## **32\. Create Service in Suspicious File Path**

This use case identifies a new Windows service being created where the executable path is in an unusual location (e.g., C:\\Users\\ or C:\\Temp\\) instead of standard system directories.

* **Prerequisite:** You need a **Custom Event Property (CEP)** to parse the Service\_File\_Name from the Windows event payload. Let's call this CEP ServiceFilePath.

### **QRadar \- Real-Time Rule**

* Navigate to Rules and create a **New Event Rule**.  
* **Define Conditions:**  
  * Apply the test: and when the Event ID is 7045 (A new service was installed).  
  * Apply the test: and when the custom property ServiceFilePath matches the following regular expression: .\*\\.exe (Ensure it's an executable).  
  * Apply the test: and when the custom property ServiceFilePath does not match the following regular expression (case-insensitive): ^(C:\\\\Windows\\\\|C:\\\\Program Files|%systemroot%\\\\).\*  
* **Configure the Response:** Dispatch a new event for "New Service Created in Suspicious Location" and create a high-severity (8) offense.

### **QRadar \- AQL Investigation Search**
```
SELECT  
   DATEFORMAT(startTime, 'YYYY-MM-dd HH:mm:ss') as "Time",  
   "Service Name",  
   "Service File Path" \-- This is a CEP  
FROM  
    events  
WHERE  
    "Event ID" \= 7045  
    AND "Service File Path" ILIKE '%.exe'  
    AND "Service File Path" NOT ILIKE 'C:\\Windows\\%' AND "Service File Path" NOT ILIKE 'C:\\Program Files\\%' AND "Service File Path" NOT ILIKE 'C:\\ProgramData\\%'  
LAST 30 DAYS  
```
