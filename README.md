# VRV_Security_Log_Analysis-

**Problem Statement**

**Objective**: Write a Python script to analyze a web server log file (sample.log) and extract key insights for cybersecurity purposes. The script should:
1. Count Requests Per IP Address:
Identify all unique IP addresses from the log file.
Calculate the number of requests made by each IP address.
Display the results sorted in descending order of request counts.

2. Identify the Most Frequently Accessed Endpoint:
Extract all resource paths (endpoints) from the log file.
Determine the endpoint accessed the highest number of times.
Provide the endpoint name and the number of accesses.
3. Detect Suspicious Activity:
Identify IP addresses with repeated failed login attempts (e.g., HTTP status code 401 or "Invalid credentials").
Flag IPs with failed attempts exceeding a configurable threshold (default: 10).
4. Output Results:
Display results in a clean and organized format in the terminal.
Save results to a CSV file (log_analysis_results.csv) with the following structure:
Requests per IP: Columns: IP Address, Request Count
Most Accessed Endpoint: Columns: Endpoint, Access Count
Suspicious Activity: Columns: IP Address, Failed Login Count


**Solution Description**

**Overview:** The solution processes a web server log file in a single pass to ensure efficiency. The script is modular, making it easy to maintain and extend. Results are displayed in the terminal and saved to a CSV file.

**Solution Details**

**Input:**

**Log File:** sample.log contains entries in a typical web server log format, e.g.:

192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512


**Implementation:**

1. Count Requests Per IP:

Extract IP addresses using a regular expression.

Use a dictionary to maintain a count for each IP address.

Sort the IPs by their request counts for display.


2. Identify the Most Frequently Accessed Endpoint:
Extract endpoints (resource paths) using a regular expression.
Use another dictionary to count accesses per endpoint.
Identify the endpoint with the maximum count.

3. Detect Suspicious Activity:
Identify failed login attempts using HTTP status code 401 or the text "Invalid credentials."
Maintain a count of failed attempts per IP address.
Filter IPs exceeding the threshold for display and CSV output.
4. Output Results:
Print the results in the terminal:
Request counts per IP.
Most accessed endpoint and its count.
Suspicious activity with IPs and failed login counts.
Save all results to a CSV file for archival and further analysis.


**Script Structure:**

1. Main Script:

log_analysis.py: The Python script implementing the solution.
2. Log File:

sample.log: The input log file.
3. Output File:
log_analysis_results.csv: CSV file containing the analysis results.


**Features:**

1. Efficiency:

Processes the log file in a single pass.

Minimal memory usage by using dictionaries and default values.

2. Customization:
Configurable threshold for detecting suspicious activities.

3. Clear Output:
Displays results in a readable terminal format and saves them in a structured CSV file.


**Results in CSV:**

The CSV file (log_analysis_results.csv) contains:

1. Requests per IP:

IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
10.0.0.2             92


2. Most Accessed Endpoint:

Endpoint             Access Count
/home                403


3. Suspicious Activity:

IP Address           Failed Login Count
192.168.1.100        56
203.0.113.34         12




---

Execution Steps:

1. Place log_analysis.py and sample.log in the same directory.


2. Run the script:

python log_analysis.py


3. View results in the terminal and the generated CSV file (log_analysis_results.csv).


Final Deliverables:

1. Python Script: log_analysis.py


2. Sample Log File: sample.log


3. Generated CSV File: log_analysis_results.csv
