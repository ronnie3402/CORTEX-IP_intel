#!/usr/bin/env python3
from dotenv import load_dotenv
import os
import ipaddress
import sqlite3 
import asyncio
import aiohttp
import csv
import json
import time
from colorama import Fore, Style, init
from datetime import datetime,timezone

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)
load_dotenv()

# Load API credentials from environment variables for security
API_VIRUS_TOTAL = os.getenv("API_KEY_VIRUS_TOTAL")
API_ABUSE_IDB = os.getenv("API_KEY_ABUSE_IDB")


# Semaphore: Limits concurrency to 5 simultaneous requests to prevent API rate-limiting
limit = asyncio.Semaphore(5)

# Severity Configuration: Define high and medium risk threat categories
HIGH_RISK_CATS = ["DDoS Attack", "Brute-Force", "SSH", "IoT Hacking"]
MEDIUM_RISK_CATS = ["Port Scan", "Bad Web Bot", "Web Analyzer"]

# Mapping AbuseIPDB category IDs to human-readable labels
category_map = {
        3: "Fraud Orders", 4: "DDoS Attack", 9: "Open Proxy", 10: "Web Spam",
        11: "Email Spam", 14: "Port Scan", 18: "Brute-Force", 19: "Bad Web Bot",
        21: "Web Analyzer", 22: "SSH", 23: "IoT Hacking"
        }

# Global list to aggregate results for final batch reporting (CSV/JSON)
results_summary = []


def init_db():
    #Initializes the local SQLite database to store threat intelligence.
    #Uses JSON serialization for API responses and timestamps for cache expiration.
    conn = sqlite3.connect('threat_intel.db')
    c = conn.cursor()

    # Define the schema: IP as Primary Key, JSON strings for flexibility, and UNIX timestamps
    c.execute('''CREATE TABLE IF NOT EXISTS ip_cache
                 (ip TEXT PRIMARY KEY, 
                  abuse_json TEXT, 
                  vt_json TEXT, 
                  timestamp REAL)''')
    conn.commit()
    conn.close()

def purge_old_cache(hours=12):
    #Automatically removes expired cache entries from the database 
    #to optimize storage and ensure data relevance.

    # Establish connection to the local threat intelligence database
    conn = sqlite3.connect('threat_intel.db')
    c = conn.cursor()

    # Calculate the expiration threshold (default is 12 hours)
    limit = time.time() - (hours * 3600)

    # Delete records that are older than the calculated limit
    c.execute("DELETE FROM ip_cache WHERE timestamp < ?", (limit,))

    # Commit changes and release database resources
    conn.commit()
    conn.close()



def get_cached_intel(ip, hours=6):
    #Retrieves threat intelligence from the local database if it exists 
    #and is within the specified freshness threshold (TTL).
    
    conn = sqlite3.connect('threat_intel.db')
    c = conn.cursor()

    # Calculate the timestamp limit (Time-To-Live) for data freshness
    limit = time.time() - (hours * 3600)
    
    # Query only if the data is fresh (not older than the threshold)
    c.execute("SELECT abuse_json, vt_json FROM ip_cache WHERE ip=? AND timestamp > ?", (ip, limit))
    res = c.fetchone()
    conn.close()
    
    if res:
        # Deserialize JSON strings back into Python dictionaries
        return json.loads(res[0]), json.loads(res[1])
    return None




def save_to_cache(ip, abuse_data, vt_data):
    #Saves or updates threat intelligence data in the local SQLite database.
    #Serializes API responses into JSON format for efficient storage.
    
    # Establish connection to the local threat intelligence database
    conn = sqlite3.connect('threat_intel.db')
    c = conn.cursor()

    # Use 'INSERT OR REPLACE' to overwrite stale data for existing IPs (Update Logic)
    # Data is stored as: IP (PK), AbuseIPDB JSON, VirusTotal JSON, and current Timestamp
    c.execute("INSERT OR REPLACE INTO ip_cache VALUES (?, ?, ?, ?)",
              (ip, json.dumps(abuse_data), json.dumps(vt_data), time.time()))
    
    # Commit changes and close the connection
    conn.commit()
    conn.close()



def calculate_risk(score, vt_malicious, vt_suspicious, cats, reports,usage,last_rep,isp):

    #Calculates the final Risk Score and Confidence Level by analyzing data from multiple sources, considering provider trust, activity recency, and threat categories.
    
    # Normalize input data to prevent errors during string operations
    isp = str(isp) if isp else ""
    usage = str(usage) if usage else ""
    cats = str(cats) if cats else ""

    # Define Trusted Infrastructure Providers (DNS, Security, and Cloud)
    HIGH_TRUST_LIST = ["google", "cloudflare", "akamai", "fastly", "quad9", "cisco"]
    CLOUD_LIST = ["digitalocean", "linode", "amazon", "aws", "azure", "oracle", "github"]

    # Identify if the IP belongs to a trusted or cloud provider
    is_high_trust = any(p in isp.lower() or p in usage.lower() for p in HIGH_TRUST_LIST)
    is_cloud = any(p in isp.lower() or p in usage.lower() for p in CLOUD_LIST)
    is_trusted = is_high_trust or is_cloud
    
    risk_score = 0
    confidence = 20  # Base confidence level for completed scans
    reasons = []

    # 1. AbuseIPDB Weightage (Confidence Score based)
    if score >= 80:
        risk_score += 40
        reasons.append("High AbuseIPDB confidence score")
    elif score >= 50:
        risk_score += 25
        reasons.append("Moderate AbuseIPDB confidence score")
    elif score >= 20:
        risk_score += 10
    

    # 2. VirusTotal Weightage (Engine Detections)
    if vt_malicious >= 10:
        risk_score += 35
        reasons.append("Multiple VirusTotal engines detected malware")
    elif vt_malicious >= 3:
        risk_score += 20
        reasons.append("Some VirusTotal engines flagged this IP")

    if vt_suspicious >= 5:
        risk_score += 10
        reasons.append("High suspicious detections on VirusTotal")
    
    # 3. Infrastructure Context (Hosting/VPS tends to be more volatile)
    if "hosting" in usage.lower() or "data center" in usage.lower():
            risk_score += 10
            reasons.append("IP belongs to hosting/VPS infrastructure")
    
    # 4. Threat Category Severity (Context-Aware Analysis)
    for cat in cats.split(","):
        cat = cat.strip()

        if cat in HIGH_RISK_CATS:
            if not is_trusted:
                risk_score += 15
                reasons.append(f"High-risk activity detected: {cat}")
            else:
                reasons.append(
                    f"Reported {cat} likely false-positive (trusted infrastructure)"
                )
            break

        elif cat in MEDIUM_RISK_CATS:
            if not is_trusted:
                risk_score += 8
                reasons.append(f"Recon activity detected: {cat}")
            else:
                reasons.append(
                    f"Recon activity ({cat}) observed on trusted infrastructure"
                )

    # 5. Temporal Analysis (Recency of Reports)
    
    if last_rep and last_rep != "Never":
        try:
            last_dt = datetime.fromisoformat(last_rep.replace("Z", "+00:00"))
            days_diff = (datetime.now(timezone.utc) - last_dt).days

            if days_diff <= 7:
                risk_score += 8
                reasons.append("Very recent abuse activity detected (last 7 days)")
            elif days_diff <= 30:
                risk_score += 5
                reasons.append("Recent abuse activity detected")
        except:
            pass


    # 6. Community Consensus
    if reports >= 50:
        risk_score += 10
        reasons.append("High number of community abuse reports")

    # 7. Trust Adjustments (Reduction for known good providers)
    if is_trusted and risk_score > 0:
        risk_score = max(0, risk_score - 15)
        reasons.append("Risk score reduced due to trusted provider context")
    
    
    # --- CONFIDENCE LEVEL CALCULATION ---
    
    # Boost confidence for reputable providers with low risk    if is_trusted and risk_score < 10: 
        if is_high_trust:
            confidence += 80 # Google/Cloudflare -> 100% (High Confidence)
            reasons.append("Confidence boosted: Trusted provider with negligible risk")
        elif is_cloud:
            confidence += 40 # DigitalOcean/AWS -> ~65-75% (Moderate Confidence)

    # Boost confidence for cross-source correlation
    if score > 20 and vt_malicious >= 3:
        confidence += 50
    elif score > 0 or vt_malicious > 0:
        confidence += 25

    # Boost confidence based on data volume
    if reports >= 100: confidence += 30
    elif reports >= 20: confidence += 15
    
    if last_rep and last_rep != "Never":
        confidence += 20

    if risk_score < 20 and vt_malicious == 0:
        confidence += 15  # 20 + 15 = 35% (Base level for unknown but clean IPs)

    # Final adjustment for clean/unknown IPs
    if risk_score == 0:
        confidence = 100

    return min(risk_score, 100), min(confidence,100), reasons



async def process_single_ip(session, ip, force_refresh=False,folder="scans"):
    #Orchestrates the complete analysis workflow for a single IP address, including caching, API enrichment, risk calculation, and reporting.
    
    abuse_data = None
    vt_data = None
    cache_hit = False

    # 1. Local Cache Lookup (Checks for existing data younger than 6 hours)
    if not force_refresh:
        cached = get_cached_intel(ip, hours=6)
        if cached:
            abuse_data, vt_data = cached
            cache_hit = True
            print(f"{Fore.BLUE}[*] Cache Hit: Using local data for {ip} (Freshness < 6h)")
    
    # 2. External API Enrichment (Triggers if cache is missing or refresh is forced)
    if not cache_hit:
        print(f"{Fore.YELLOW}[*] Cache Miss/Forced: Querying APIs for {ip}...")
        # 1. APIs call (Async)
        ip, abuse_data, vt_data = await enrich_ip(session, ip)
    
        if abuse_data and vt_data:
            save_to_cache(ip, abuse_data, vt_data)
            print(f"{Fore.YELLOW}[*] Fresh data fetched and cached for {ip}")

    # 3. Data Integrity Check (Safely skip processing if API data is unavailable)
    if abuse_data is None or vt_data is None:
        print(f"{Fore.RED}[- ] Skipping {ip}: Failed to fetch data from APIs (Connection/Session Error)")
        return  
    
    # 4. Data Normalization (Ensures strings are safe for slicing and display)
    isp_safe = str(abuse_data.get('isp') or "N/A")
    usage_safe = str(abuse_data.get('usage') or "N/A")
    domain_safe = str(abuse_data.get('domain') or "N/A")
    cat_safe = str(abuse_data.get('categories') or "None")

    # 5. Risk Assessment & Verdict Generation
    if abuse_data and vt_data:
        
        risk_score, confidence, reasons = calculate_risk(
            abuse_data['score'], vt_data['malicious'], vt_data['suspicious'],
            abuse_data['categories'], abuse_data['reports'],
            abuse_data['usage'], abuse_data['last_reports'], abuse_data['isp']
        )
        verdict, recommendation = get_verdict(risk_score, confidence)

        # 6. Documentation (Saves the individual text report)
        save_report(ip, abuse_data, vt_data, folder, risk_score, confidence, reasons, verdict, recommendation)

        
        ip_data = {
            "IP": ip,
            "Verdict": verdict,
            "Risk": risk_score,
            "Confidence": f"{confidence}%",
            "ISP": abuse_data['isp'],
            "Country": abuse_data['country'],
            "Malicious_VT": vt_data['malicious'],
            "Recent_Reports": abuse_data['reports']
        }
        
        # 7. Batch Aggregation (Adds result to the global summary list)
        results_summary.append({
            "IP": ip, "Verdict": verdict,"Recommendations": recommendation,"Risk": risk_score, "Confidence": f"{confidence}%",
            "ISP": abuse_data['isp'], "Country": abuse_data['country'],
        })
        
        # 8. Visual Console Output (Formatted report box)
        color = Fore.RED if risk_score >= 50 else (Fore.YELLOW if risk_score >= 20 else Fore.GREEN)
        
        print(f"\n{color}╔" + "═"*60 + "╗")
        print(f"{color}║ [ANALYSIS REPORT FOR: {ip.ljust(35)}] ║")
        print(f"{color}╠" + "═"*60 + "╣")
        
        # Combined Intelligence Section
        print(f"{color}║ VERDICT     : {verdict.ljust(45)} ║")
        print(f"{color}║ RISK SCORE  : {str(risk_score).ljust(3)}/100 | CONFIDENCE: {str(confidence).ljust(3)}% {'[!]'.ljust(11) if risk_score >= 50 else ' '.ljust(11)} ║")
        print(f"{color}╠" + "─"*60 + "╢")
        
        # AbuseIPDB Info
        print(f"{color}║ [AbuseIPDB] : Score: {str(abuse_data['score']).ljust(3)}% | Reports: {str(abuse_data['reports']).ljust(5)} | Users: {str(abuse_data['Users']).ljust(4)} ║")
        print(f"{color}║ ISP/Usage   : {isp_safe[:25].ljust(25)} ({usage_safe[:15].ljust(15)}) ║")
        
        # VirusTotal Info
        print(f"{color}║ [VirusTotal]: Malicious: {str(vt_data['malicious']).ljust(2)} | Suspicious: {str(vt_data['suspicious']).ljust(2)} | Rep: {str(vt_data['reputation']).ljust(4)} ║")
        print(f"{color}║ Network     : {str(vt_data['network']).ljust(45)} ║")
        
        # Geo & Categories
        print(f"{color}║ Geo/Domain  : {abuse_data.get('country', '??').ljust(2)} | {domain_safe[:40].ljust(40)} ║")
        print(f"{color}║ Categories  : {cat_safe[:45].ljust(45)}... ║")
        
        print(f"{color}╚" + "═"*60 + "╝")

def generate_batch_reports(folder="scans"):
    #Consolidates scan results into CSV and JSON formats and displays a high-level console summary of critical threats.
     
    if not results_summary:
        return
    
    # Generate a unique timestamp for batch files
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # 1. Export summary to CSV for spreadsheet analysis
    csv_file = os.path.join(folder, f"batch_summary_{timestamp}.csv")
    keys = results_summary[0].keys()
    with open(csv_file, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, keys)
        dict_writer.writeheader()
        dict_writer.writerows(results_summary)

    # 2. Export data to JSON for SIEM (Security Information and Event Management) integration
    json_file = os.path.join(folder, f"siem_data_{timestamp}.json")
    with open(json_file, 'w') as f:
        json.dump(results_summary, f, indent=4)
    print(f"\n{Fore.CYAN}[+] Batch summaries saved with timestamp: {timestamp}")
    
    # --- FINAL CONSOLE SUMMARY ---
    total_scanned = len(results_summary)
    critical_count = sum(1 for ip in results_summary if ip['Risk'] >= 50)
    
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"{Fore.CYAN} 🛡️  SCAN SUMMARY REPORT")
    print(f"{Fore.CYAN}{'='*65}")
    print(f"{Fore.WHITE} Total IPs Scanned : {total_scanned}")
    print(f"{Fore.RED if critical_count > 0 else Fore.GREEN} Critical Threats  : {critical_count}")
    print(f"{Fore.CYAN}{'-'*65}")

    if critical_count > 0:
        print(f"{Style.BRIGHT}{Fore.RED}🚨 ACTION REQUIRED: TOP CRITICAL THREATS")
        
        # Sort threats by Risk Score in descending order
        sorted_ips = sorted(results_summary, key=lambda x: x['Risk'], reverse=True)
        
        # Display top 5 critical findings
        for ip_data in sorted_ips[:5]: # Top 5 dikhayega
            if ip_data['Risk'] >= 50:
                
                print(f"\n{Fore.RED}▶ IP: {ip_data['IP']} (Risk: {ip_data['Risk']}/100)")
                print(f"{Fore.YELLOW}  Verdict: {ip_data['Verdict']}")
                print(f"{Fore.WHITE}  Action : {Style.BRIGHT}{ip_data['Recommendations']}")
                
                # Assign dynamic response action based on risk severity
                action = "IMMEDIATE BLOCK REQUIRED" if ip_data['Risk'] >= 80 else "MANUAL INVESTIGATION NEEDED"
                print(f"{Fore.WHITE}  Action : {Style.BRIGHT}{action}")
    else:
        print(f"{Fore.GREEN}✅ No critical threats detected in this batch.")

    print(f"\n{Fore.CYAN}{'='*65}")


def get_verdict(risk_score,confidence):
    #Classifies the threat level and provides security recommendations based on the calculated risk score and data confidence. 
    
    verdict = ""
    recommendation = "" 

    # Category 1: CRITICAL / HIGH RISK
    if risk_score >= 50:
        if confidence >= 80:
            verdict = "CRITICAL / ACTIVE THREAT"
            recommendation = "CONFIRMED THREAT: Immediately block IP at Firewall and isolate affected systems."
        else:
            verdict = "HIGH RISK (UNVERIFIED)"
            recommendation = "SUSPICIOUS ACTIVITY: Do NOT block yet. Perform manual investigation and check internal logs."

    # Category 2: MEDIUM RISK / SUSPICIOUS
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
        if confidence >= 70:
            recommendation = "Monitor traffic closely. Correlate with login failures."
        else:
            recommendation = "Low evidence of malice. But Keep an eye on this IP in your SIEM."

    # Category 3: LOW RISK
    elif risk_score >= 5:
        verdict = "LOW RISK"
        recommendation = "General noise (scanners). No immediate action needed."

    # Category 4: CLEAN
    else:
        verdict = "CLEAN"
        recommendation = "Safe IP. No action required."

    return verdict, recommendation

    


def ip_validation(ipaddr):
    #Parses, validates, and filters IP addresses from files or raw input strings.
    #Excludes private, local, and invalid IP addresses.

    raw_ips = []
    
    # Check if the input provides a valid file path
    if os.path.isfile(ipaddr):
        print(f"{Fore.CYAN}[*] Reading IPs from file: {ipaddr}")
        try:
            with open(ipaddr, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: 
                        continue
                    # Handle both line-separated and comma-separated IPs within the file
                    if "," in line:
                        raw_ips.extend([ip.strip() for ip in line.split(",")])
                    else:
                        raw_ips.append(line)
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading file: {e}")
    
    # Handle direct comma-separated string input
    elif "," in ipaddr:
        raw_ips = [ip.strip() for ip in ipaddr.split(",")]
    
    # Treat input as a single standalone IP address
    else:
        raw_ips = [ipaddr.strip()]

    # Filter and validate extracted IP addresses
    valid_ips = []
    skipped_count = 0
    
    for ip in raw_ips:
        try:
            # Clean string and convert to ip_address object for validation
            clean_ip = ip.strip()
            ip_obj = ipaddress.ip_address(clean_ip)
            
            # Exclude private/local IPs (irrelevant for external threat intelligence)
            if ip_obj.is_private:
                skipped_count += 1
                continue
            valid_ips.append(ip)
        except ValueError:
            # Log and skip malformed IP strings
            print(f"{Fore.RED}[-] Skipping Invalid IP: {ip}")
            
    if skipped_count > 0:
        print(f"{Fore.YELLOW}[!] Skipped {skipped_count} private/local IP(s).")

    # Return a unique list of valid IPs to prevent redundant processing    
    return list(set(valid_ips)) 



async def check_abuseipdb(session, ipaddr):
    #Queries AbuseIPDB API v2 to fetch reputation data and abuse history.
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': API_ABUSE_IDB # Authenticates using environment variable
    }
    params = {
        'ipAddress': ipaddr,
        'maxAgeInDays': '90',   # Analyze data from the last 90 days
        'verbose': ''           # Enables detailed report history
    }

    # Respect API concurrency limits using the defined semaphore
    async with limit: 
        try:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    json_res = await response.json()
                    data = json_res['data']
                    
                    # Core Reputation Metrics
                    score = data.get('abuseConfidenceScore', 0)
                    reports = data.get('totalReports', 0)
                    last_rep = data.get('lastReportedAt', 'Never')

                    # Geographical and Network Metadata
                    country = data.get('countryCode', 'N/A')
                    usage = data.get('usageType', 'N/A')
                    isp = data.get('isp', 'N/A')
                    is_public = data.get('isPublic', 'N/A')
                    domain = data.get('domain', 'N/A')
                    users = data.get('numDistinctUsers', 0)

                    # Extract and Map Abuse Categories to human-readable names
                    raw_reports = data.get('reports', [])
                    detected_categories = set()
            
                    for report in raw_reports:
                        cat_ids = report.get('categories', [])
                        for cid in cat_ids:
                            # Map category ID to descriptive name from global category_map
                            detected_categories.add(category_map.get(cid, f"Unknown({cid})"))

                    cat_string = ", ".join(detected_categories) if detected_categories else "None"

                    # Return structured data dictionary for report consolidation
                    return {
                        'score': score,
                        'reports': reports,
                        'country': country,
                        'Users': users,
                        'isp': isp,
                        'usage': usage,
                        'domain': domain,
                        'categories': cat_string,
                        'last_reports': last_rep,
                        'Public IP': is_public
                    }
                else:
                    print(f"[-] AbuseIPDB Error: {response.status}")
                    return None
        except Exception as e:
            print(f"[-] AbuseIPDB Async Error for {ipaddr}: {e}")
            return None



async def check_virustotal(session,ipaddr):
    #Queries VirusTotal API v3 for IP reputation and analysis statistics.

    print(f"[*] Querying VirusTotal for {ipaddr}...")
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}'
    headers = {'x-apikey': API_VIRUS_TOTAL}

    # Use semaphore to respect API rate limits and prevent session exhaustion
    async with limit: 
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    json_res = await response.json()
                    attributes = json_res['data']['attributes']
                    
                    # Extract reputation score and analysis statistics
                    reputation = attributes.get('reputation', 0)
                    stats = attributes.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    # Extract infrastructure and geographical context
                    country = attributes.get('country', 'N/A')
                    as_owner = attributes.get('as_owner', 'N/A')
                    network = attributes.get('network', 'N/A')
                    
                    # Convert Unix timestamp to a human-readable date format
                    last_date_unix = attributes.get('last_analysis_date', 0)
                    last_date = datetime.fromtimestamp(last_date_unix).strftime('%Y-%m-%d') if last_date_unix else "N/A"

                    # Return formatted dictionary for report generation
                    return {
                        'malicious': malicious,
                        'suspicious': suspicious,
                        'reputation': reputation,
                        'country': country,
                        'owner': as_owner,
                        'network': network,
                        'last_date': last_date
                    }
                else:
                    # Log API error status codes
                    print(f"[-] VirusTotal Error: {response.status}")
                    return None
        except Exception as e:
            # Handle unexpected network or processing exceptions
            print(f"[-] VT Async Error for {ipaddr}: {e}")
            return None



async def enrich_ip(session, ipaddr):
    #Fetches threat intelligence from multiple sources concurrently.
    
    try:
        # Define asynchronous tasks for AbuseIPDB and VirusTotal
        abuse_task = check_abuseipdb(session, ipaddr)
        vt_task = check_virustotal(session, ipaddr)
        
        # Execute both tasks in parallel. 
        # 'return_exceptions=True' ensures that if one API fails, the other can still complete.
        results = await asyncio.gather(abuse_task, vt_task, return_exceptions=True)
        
        # Validate results: If a task returned an Exception, set data to None
        abuse_data = results[0] if not isinstance(results[0], Exception) else None
        vt_data = results[1] if not isinstance(results[1], Exception) else None
        
        return ipaddr, abuse_data, vt_data
    except Exception as e:
        # Log any unexpected errors during the enrichment process
        print(f"[-] Enrichment Error for {ipaddr}: {e}")
        return ipaddr, None, None



def save_report(ipaddr, abuse_data, vt_data, user_path, risk_score, confidence, reasons, verdict, recommendation):
    #Generates and saves a detailed text report for a specific IP address.

    # Normalize directory path for cross-platform compatibility
    folder_path = os.path.normpath(user_path)

    # Ensure the target directory exists; fallback to default if creation fails
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
            print(Fore.CYAN + f"[+] Created directory structure: {folder_path}")
        except Exception as e:
            print(Fore.RED + f"[-] Could not create folder: {e}")
            folder_path = "scans" # Fallback to default


    # Prepare file metadata and unique filename
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{ipaddr}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    full_path = os.path.join(folder_path, filename)
    

    # Extract Intelligence from AbuseIPDB data
    score = abuse_data.get('score', 0)
    reports = abuse_data.get('reports', 0)
    last_rep = abuse_data.get('last_reports', 'Never')
    country = abuse_data.get('country', 'N/A')
    usage = abuse_data.get('usage', 'N/A')
    isp = abuse_data.get('isp', 'N/A')
    is_public = abuse_data.get('Public IP', 'N/A')
    domain = abuse_data.get('domain', 'N/A')
    users = abuse_data.get('users', 0)
    cats = abuse_data.get('categories', 'None')


    # Extract Intelligence from VirusTotal data
    vt_malicious = vt_data.get('malicious', 0)
    vt_suspicious = vt_data.get('suspicious', 0)
    vt_reputation = vt_data.get('reputation', 0)
    vt_country = vt_data.get('country', 'N/A')
    vt_owner = vt_data.get('owner', 'N/A')
    vt_network = vt_data.get('network', 'N/A')
    vt_last_date = vt_data.get('last_date', 'N/A')

    try:
        with open(full_path, "w") as f:
            # Report Header
            f.write("="*50 + "\n")
            f.write(f"      THREAT REPORT FOR: {ipaddr}\n")
            f.write("="*50 + "\n")

            # Metadata Section
            f.write("REPORT METADATA\n")
            f.write("-"*20 + "\n")
            f.write(f"Report Generated At: {now}\n")
            f.write(f"Target IP Address: {ipaddr}\n\n")
            f.write("-"*20 + "\n")

            # AbuseIPDB Intelligence Data
            f.write("ABUSEIPDB INTELLIGENCE\n")
            f.write("-"*20 + "\n")
            f.write(f"AbuseIPDB Score: {score}%\n")
            f.write(f"Reports: {reports}\n")
            f.write(f"Last Report: {last_rep}\n")
            f.write(f"Country: {country}\n")
            f.write(f"Usage: {usage}\n")
            f.write(f"ISP: {isp}\n")
            f.write(f"Public IP: {is_public}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Users: {users}\n")
            f.write(f"Category: {cats}\n")

            # VirusTotal Intelligence Data
            f.write("\n" + "-"*20 + " VirusTotal Intelligence " + "-"*20 + "\n")
            f.write(f"Reputation Score: {vt_reputation}\n")
            f.write(f"Malicious Engines: {vt_malicious}\n")
            f.write(f"Suspicious Engines: {vt_suspicious}\n")
            f.write(f"ASN / Owner: {vt_owner}\n")
            f.write(f"Network Range: {vt_network}\n")
            f.write(f"Country: {vt_country}\n")
            f.write(f"Last Analysis Date: {vt_last_date}\n")

            # --- FINAL ASSESSMENT SECTION ---
            f.write("-" * 60 + "\n")
            
            
            # Risk calculation and verdict generation
            risk_score, confidence, reasons = calculate_risk(
                score, vt_malicious, vt_suspicious, cats, reports,usage,last_rep,isp
            )
            
            verdict, recommendation = get_verdict(risk_score,confidence)
            
            # Write Final Results to File
            f.write(f"FINAL VERDICT: {verdict}\n")
            f.write(f"RISK SCORE: {risk_score}/100\n")
            f.write(f"CONFIDENCE: {confidence}%")
            
            # Detailed reasoning for the risk score
            f.write("\nReasoning:\n")
            for r in reasons:
                f.write(f" - {r}\n")

            # Actionable security recommendations
            f.write("\nRecommended Actions:\n")
            f.write(recommendation + "\n")

            f.write("="*50 + "\n")
            
        print(Fore.GREEN + f"\n[+] Report successfully saved at: {full_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to write file: {e}")



async def main():
    # Initialize local database and clear expired cache entries (older than 12h)
    init_db() 
    purge_old_cache(hours=12) 

    # Display Tool Header
    print(Fore.CYAN + Style.BRIGHT + "="*60)
    print(Fore.CYAN + Style.BRIGHT + "      CORTEX-IP_intel - ASYNC THREAT INTELLIGENCE ENGINE        ")
    print(Fore.CYAN + Style.BRIGHT + "="*60)

    # Tool Capability Indicators (Optional but looks cool)
    print(Fore.BLUE+ "[⚡] Engine: Asyncio | [🗄️] Cache: SQLite | [🛡️] API: VT & AbuseIPDB")
    print(Fore.CYAN + "-"*65)
    # Get user input and validate IP addresses
    user_input = input("\n[?] Enter IP, Bulk IPs (comma), or File Path: ").strip()
    ip_list = ip_validation(user_input) # Humne Phase 2 mein jo banaya tha

    # Exit if no valid IP addresses are found
    if not ip_list:
        print(Fore.RED + "[!] No valid IPs to process.")
        print(Fore.RED +"[!] Exiting.")
        return
    
    # Create a unique session folder based on the current timestamp
    session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    session_path = os.path.join("scans", f"batch_{session_id}")
    
    if not os.path.exists(session_path):
        os.makedirs(session_path)
        print(f"{Fore.CYAN}[*] Created Session Folder: {session_path}")
    
    # Ask user if they want to bypass cache for a fresh scan
    choice = input(f"\n{Fore.YELLOW}[?] Force fresh scan for all? (y/N): ").lower()
    force = True if choice == 'y' else False

    # Initialize Async Engine using aiohttp session
    async with aiohttp.ClientSession() as session:
        print(Fore.YELLOW + f"[*] Launching {len(ip_list)} concurrent scans...")
        
        # Prepare the list of asynchronous tasks
        tasks = [process_single_ip(session, ip,force_refresh=force,folder=session_path) for ip in ip_list]
        
        # Execute all tasks concurrently
        await asyncio.gather(*tasks)

    # Generate final batch reports (CSV/JSON) in the session folder
    generate_batch_reports(folder=session_path)
    
    print(Fore.GREEN + "\n[+] All scans completed successfully.")

if __name__ == "__main__":
    # Start the asynchronous event loop with clean exit handling
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user.")