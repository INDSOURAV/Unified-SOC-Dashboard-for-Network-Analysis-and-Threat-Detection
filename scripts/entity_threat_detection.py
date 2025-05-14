import json
import requests
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
import os

# ✍️ Fill these with your API keys
VIRUSTOTAL_API_KEY = '8e3f37988f2d6f1e488138bb8f10e869d8f5a4b9063d21c3b41d22ec8f38396a'
ABUSEIPDB_API_KEY = 'de3d1323dc1044fecbf275c5403d7b23b3ff9b5a470092db677c35fb0484b9d1c064b3ab4888c90e'

# 🧠 API Functions
def check_file_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            file_name = attributes.get('file_name', 'Unknown File')
            first_submission_date = datetime.fromtimestamp(attributes.get('first_submission_date', 0), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            last_analysis_date = datetime.fromtimestamp(attributes.get('last_analysis_date', 0), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            last_analysis_stats = attributes.get('last_analysis_stats', {})

            return {
                "file_hash": file_hash,
                "file_name": file_name,
                "first_submission_date": first_submission_date,
                "last_analysis_date": last_analysis_date,
                "last_analysis_stats": {
                    "harmless": last_analysis_stats.get('harmless', 0),
                    "malicious": last_analysis_stats.get('malicious', 0),
                    "suspicious": last_analysis_stats.get('suspicious', 0),
                    "timeout": last_analysis_stats.get('timeout', 0),
                    "undetected": last_analysis_stats.get('undetected', 0)
                }
            }
        else:
            return {"error": response.text}
    except Exception as e:
        return {"exception": str(e)}

def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "domain": data.get("domain"),
                "hostnames": data.get("hostnames"),
                "last_reported_at": data.get("lastReportedAt")
            }
        else:
            return {"error": response.text}
    except Exception as e:
        return {"exception": str(e)}

def check_domain_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            creation_date = datetime.fromtimestamp(attributes.get('created_at', 0), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            last_analysis_date = datetime.fromtimestamp(attributes.get('last_analysis_date', 0), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            last_modification_date = datetime.fromtimestamp(attributes.get('last_modification_date', 0), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            last_analysis_stats = attributes.get('last_analysis_stats', {})

            return {
                "domain": domain,
                "categories": list(attributes.get('categories', {}).values()),
                "creation_date": creation_date,
                "last_analysis_date": last_analysis_date,
                "last_modification_date": last_modification_date,
                "last_analysis_stats": {
                    "harmless": last_analysis_stats.get('harmless', 0),
                    "malicious": last_analysis_stats.get('malicious', 0),
                    "suspicious": last_analysis_stats.get('suspicious', 0),
                    "timeout": last_analysis_stats.get('timeout', 0),
                    "undetected": last_analysis_stats.get('undetected', 0)
                }
            }
        else:
            return {"error": response.text}
    except Exception as e:
        return {"exception": str(e)}

# 🚀 Main enrichment function
def entity_threat_checking(input_json_path):
    with open(input_json_path, 'r') as f:
        data = json.load(f)

    enriched_data = {
        "ips": {},
        "domains": {},
        "file_hashes": {}
    }

    for ip in data.get("IPs", []):
        print(f"[*] Checking IP: {ip}")
        enriched_data["ips"][ip] = check_ip_abuseipdb(ip)
        time.sleep(1)

    for domain in data.get("Domains", []):
        if "local" in domain:
            break
        else:
            print(f"[*] Checking Domain (VirusTotal): {domain}")
            enriched_data["domains"][domain] = check_domain_virustotal(domain)
            time.sleep(1)


    for file_hash in data.get("Files", {}).keys():
        print(f"[*] Checking File Hash (VirusTotal): {file_hash}")
        enriched_data["file_hashes"][file_hash] = {
            "analysis": check_file_hash_virustotal(file_hash)
        }
        time.sleep(1)

    output_path = os.path.join("uploads", "enriched_output.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(enriched_data, f, indent=4)

    print(f"[+] Enriched data saved to {output_path}")
    return output_path
