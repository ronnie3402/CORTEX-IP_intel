# 🧠 CORTEX-IP_intel

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/API-VirusTotal%20%7C%20AbuseIPDB-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Focus-Threat%20Intelligence-red?style=flat-square"/>
</p>

> **A Fast and Smart Tool to Check IP Threat Intelligence**

<img width="800" height="441" alt="ip intel" src="https://github.com/user-attachments/assets/5be6163b-f4d2-4abc-a6dc-0bf7e416db5e" />


---

## Overview
A fast, asynchronous, and smart IP Threat Intelligence tool built specifically for Security Analysts and Blue Teamers. CORTEX-IP_intel rapidly analyzes bulk IP addresses by querying the AbuseIPDB and VirusTotal APIs, generating consolidated risk scores and forensic reports.

---

## ✨ Features
* **⚡ Very Fast:** It scans many IPs at the same time (Asynchronous).
* **🧠 Smart Brain:** It calculates a "Risk Score" based on reports and engine detections.
* **🗄️ Save Data:** It saves results in a local database (SQLite) so you don't call APIs again for the same IP.
* **📊 Automatic Reports:** It creates CSV, JSON, and Text reports in organized folders.
* **🛡️ Smart Filtering:** Automatically detects and skips Private/Internal IP addresses (like 192.168.x.x) to save API credits and prevent errors.

* **🔄 Cache TTL (Time-To-Live):** Intelligently updates the local database if the threat data is too old, ensuring you always get fresh intelligence.

* **⚡ Cache Bypass Option:** Users can choose to bypass the local database and force a fresh API fetch whenever live data is critical.

* **📂 Session-Based Isolation:** Every scan session is saved in a unique timestamped folder to prevent data overwrite. Additionally, every generated report (CSV, JSON, TXT) inside the folder includes the Target IP and precise timestamp in its filename for perfect forensic tracking.

---

## Architecture
CORTEX-IP_intel utilizes Python's `asyncio` for concurrent API requests and a local SQLite database for caching and TTL management. It features modular parsing engines to extract specific threat metrics from deeply nested JSON responses returned by enterprise threat intel providers. Every scan session isolates data into structured directories for strict forensic integrity.

---

## 🚀 Quick Setup & Installation
⚙️ Installation & Setup (Recommended)
It is highly recommended to run this tool in a Virtual Environment to avoid dependency conflicts.

Follow these steps to get CORTEX-IP_intel running on your system:
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/ronnie3402/CORTEX-IP_intel git
   
   cd CORTEX-IP_intel

2. **Create & Activate Virtual Environment:**
      * **Windows:**

         python -m venv .venv --> Creating virtual environment.
        
         .venv\Scripts\activate --> To activate virtual environment.

      * **Linux/Kali:**
   
        python3 -m venv .venv --> Creating virtual environment.

        source .venv/bin/activate --> To activate virtual environment.

4. **Install Dependencies: Ensure you have Python installed, then run:**

      pip install -r requirements.txt

5. **Configure API Keys:**

      * Open .env.example and put your keys.

      * Rename .env.example to .env.

---

## 🖥️ How to Use

**Launch the tool using the following command:**



      python CORTEX-IP_intel.py

**Flexible Input Options:** Once the tool starts, you can provide input in three ways:
   *  **Single IP:** Just type one IP (e.g., 8.8.8.8).
   *  **Bulk IPs:** Type multiple IPs separated by commas (e.g., 1.1.1.1, 8.8.8.8).
   *  **File Input:** Provide the path to a .txt file containing a list of IPs.

---

## 📂 Report Organization
**Instead of just saving data, CORTEX-IP_intel creates a professional forensic audit trail. Every scan session is isolated in a unique folder (e.g., batch_20260209_011500) containing:**

* ***📊 CSV Batch Summary:*** A structured spreadsheet containing consolidated results of all scanned IPs. Perfect for quick filtering and executive overviews in MS Excel or Google Sheets.

* ***🛠️ JSON SIEM Data:*** Highly structured machine-readable logs. Designed for easy integration with security tools like Splunk, ELK Stack, or custom SOC dashboards.

* ***🛡️ TXT Forensic Reports:*** Individual, deep-dive forensic files for every IP. Each file (e.g., report_1.1.1.1_timestamp.txt) contains full metadata, provider trust scores, and automated analyst recommendations.

## Sample Output

<img width="1680" height="826" alt="ip intel2" src="https://github.com/user-attachments/assets/2198fb0f-5544-4a26-aa1d-c61843cd7aaf" />


---

## 🧠 Technical Learnings

Building CORTEX-IP_intel helped me strengthen several practical cybersecurity and software engineering skills:

- **Threat Intelligence Integration** using AbuseIPDB and VirusTotal APIs.
- **Asynchronous Programming** for high-performance concurrent IP analysis.
- **SQLite-based Caching** to reduce API consumption and improve response times.
- **Risk Scoring** and correlation of intelligence data from multiple providers.
- **Automated Report Generation** in CSV, JSON, and TXT formats.
- **Secure Handling of API Keys** using environment variables.
- **Designing Forensic-Friendly Output Structures** for SOC and Incident Response workflows.

---

## 📜 License

This project is for educational and security analysis purposes only. 
Licensed under the [MIT License](LICENSE).

---

## 👨‍💻 Author

**Rohit** — Built for the cybersecurity community.
*Copyright (c) 2026 Rohit (ronnie3402)*
