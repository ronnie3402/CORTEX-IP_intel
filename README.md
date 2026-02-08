**Copyright (c) 2026 Rohit (ronnie3402)** **CORTEX-IP_intel - https://github.com/ronnie3402/CORTEX-IP_intel** 

**This project is for educational and security analysis purposes only.**

# 🧠 CORTEX-IP_intel
**A Fast and Smart Tool to Check IP Threat Intelligence**

CORTEX-IP_intel is a professional tool built for security analysts. It helps you check many IP addresses quickly to see if they are safe or dangerous. It uses **AbuseIPDB** and **VirusTotal** APIs to get the best data.



## ✨ Best Features
* **⚡ Very Fast:** It scans many IPs at the same time (Asynchronous).
* **🧠 Smart Brain:** It calculates a "Risk Score" based on reports and engine detections.
* **🗄️ Save Data:** It saves results in a local database (SQLite) so you don't call APIs again for the same IP.
* **📊 Automatic Reports:** It creates CSV, JSON, and Text reports in organized folders.
* **🛡️ Smart Filtering:** Automatically detects and skips Private/Internal IP addresses (like 192.168.x.x) to save API credits and prevent errors.

* **🔄 Cache TTL (Time-To-Live):** Intelligently updates the local database if the threat data is too old, ensuring you always get fresh intelligence.

* **⚡ Cache Bypass Option:** Users can choose to bypass the local database and force a fresh API fetch whenever live data is critical.

* **📂 Session-Based Isolation:** Every scan session is saved in a unique timestamped folder to prevent data overwrite. Additionally, every generated report (CSV, JSON, TXT) inside the folder includes the Target IP and precise timestamp in its filename for perfect forensic tracking.


## 🚀 Quick Setup & Installation
Follow these steps to get CORTEX-IP_intel running on your system:
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/ronnie3402/CORTEX-IP_intel git
   
   cd CORTEX-IP_intel

2. **Install Dependencies: Ensure you have Python installed, then run:**

      pip install -r requirements.txt

3. **Configure API Keys:**

      * Open .env.example and put your keys.

      * Rename .env.example to .env.

## 🖥️ How to Use

**Launch the tool using the following command:**



      python CORTEX-IP_intel.py

**Flexible Input Options:** Once the tool starts, you can provide input in three ways:
   *  **Single IP:** Just type one IP (e.g., 8.8.8.8).
   *  **Bulk IPs:** Type multiple IPs separated by commas (e.g., 1.1.1.1, 8.8.8.8).
   *  **File Input:** Provide the path to a .txt file containing a list of IPs.

## 📂 Report Organization
**Instead of just saving data, CORTEX-IP_intel creates a professional forensic audit trail. Every scan session is isolated in a unique folder (e.g., batch_20260209_011500) containing:**

* ***📊 CSV Batch Summary:*** A structured spreadsheet containing consolidated results of all scanned IPs. Perfect for quick filtering and executive overviews in MS Excel or Google Sheets.

* ***🛠️ JSON SIEM Data:*** Highly structured machine-readable logs. Designed for easy integration with security tools like Splunk, ELK Stack, or custom SOC dashboards.

* ***🛡️ TXT Forensic Reports:*** Individual, deep-dive forensic files for every IP. Each file (e.g., report_1.1.1.1_timestamp.txt) contains full metadata, provider trust scores, and automated analyst recommendations.

**Copyright (c) 2026 Rohit (ronnie3402)** **CORTEX-IP_intel - https://github.com/ronnie3402/CORTEX-IP_intel** 


