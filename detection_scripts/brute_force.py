from subprocess import check_output, CalledProcessError
from collections import defaultdict
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel
import json
from datetime import datetime
import time

# === Thresholds ===
HTTP_THRESHOLD = 5
FTP_THRESHOLD = 2

def convert_timestamp(raw_time):
    try:
        # Try standard format
        dt = datetime.strptime(raw_time.strip(), "%b %d, %Y %H:%M:%S.%f %Z")
    except Exception:
        try:
            # Try parsing without timezone
            dt = datetime.strptime(raw_time.strip(), "%b %d, %Y %H:%M:%S.%f")
        except Exception:
            # Fallback to current UTC time if all parsing fails
            dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def detect_brute_force(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    alerts = []
    http_failures = defaultdict(int)
    ftp_failures = defaultdict(int)
    brute_sources = set()
    log_entries = []

    # === HTTP Brute Force Detection ===
    try:
        print("[*] Detecting HTTP brute force...")
        cmd_http = [
            "tshark", "-r", pcap_file,
            "-Y", 'http.response.code == 401 || http.response.code == 403',
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.response.code"
        ]

        output_http = check_output(cmd_http, text=True)
        for line in output_http.strip().split("\n"):
            parts = line.strip().split("\t")
            if len(parts) >= 6:
                epoch_str, src_ip, dst_ip, host, uri, code = parts
                try:
                    timestamp = datetime.utcfromtimestamp(float(epoch_str)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                key = f"{src_ip} -> {host}{uri}"
                http_failures[key] += 1

                log_entries.append({
                    "time": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "HTTP",
                    "length": 0,
                    "info": f"HTTP {code} for {host}{uri}"
                })

        for key, count in http_failures.items():
            if count > HTTP_THRESHOLD:
                alerts.append(f"[!] HTTP Brute Force attempt detected: {key} | Failures: {count}")
                src_ip = key.split(" -> ")[0]
                brute_sources.add(src_ip)

    except CalledProcessError as e:
        alerts.append(f"[!] Error detecting HTTP brute force: {str(e)}")

    # === FTP Brute Force Detection ===
    try:
        print("[*] Detecting FTP brute force...")
        cmd_ftp = [
            "tshark", "-r", pcap_file,
            "-Y", 'ftp.response.code == 530',
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ftp.response.code"
        ]

        output_ftp = check_output(cmd_ftp, text=True)
        for line in output_ftp.strip().split("\n"):
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                epoch_str, src_ip, dst_ip, code = parts
                try:
                    timestamp = datetime.utcfromtimestamp(float(epoch_str)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                key = f"{src_ip} -> {dst_ip}"
                ftp_failures[key] += 1

                log_entries.append({
                    "time": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "FTP",
                    "length": 0,
                    "info": f"FTP {code} login failure"
                })

        for key, count in ftp_failures.items():
            if count > FTP_THRESHOLD:
                alerts.append(f"[!] FTP Brute Force attempt detected: {key} | Failures: {count}")
                src_ip = key.split(" -> ")[0]
                brute_sources.add(src_ip)

    except CalledProcessError as e:
        alerts.append(f"[!] Error detecting FTP brute force: {str(e)}")

    # === Threat Hunting Info ===
    try:
        with open(enrich_json_path, "r") as f:
            enrich_data = json.load(f)
            all_ips_data = enrich_data.get("ips", {})
    except Exception:
        all_ips_data = {}

    threat_hunting_info = {}
    for ip in brute_sources:
        threat_hunting_info[ip] = all_ips_data.get(ip, {
            "ip": ip,
            "abuse_confidence_score": "N/A",
            "total_reports": "N/A",
            "country_code": "N/A",
            "domain": "N/A",
            "hostnames": [],
            "last_reported_at": "N/A"
        })

    threat_hunting_raw = refine_threat_intel(threat_hunting_info)
    threat_hunting_summary = ""
    for ip, summary in threat_hunting_raw.items():
        threat_hunting_summary += f"<div class='mb-4'><strong>{ip}</strong><br>{summary}</div><br>"

    # === AI Summary ===
    summary = "No brute-force activity detected."
    if alerts:
        try:
            summary = generate_dynamic_summary(
                "Brute Force (HTTP/FTP)",
                list(brute_sources),
                macs=[],
                packet_count=len(log_entries)
            )
        except Exception:
            summary = "Brute-force behavior detected, but AI summary failed."

    return {
        "category": "Brute Force (HTTP/FTP)",
        "count": len(alerts),
        "details": alerts,
        "unique_ips": list(brute_sources),
        "mac_addresses": [],
        "total_packets": len(log_entries),
        "log_entries": log_entries,
        "summary": summary,
        "threat_hunting_summary": threat_hunting_summary
    }
