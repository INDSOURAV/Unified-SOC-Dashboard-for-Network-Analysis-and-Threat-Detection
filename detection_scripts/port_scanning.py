from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from datetime import datetime
import json
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel  # <== NEW import

# === Threshold ===
PORT_SCAN_THRESHOLD = 30  # Unique destination ports per IP

def detect_port_scanning(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {
            "category": "Port Scanning",
            "count": 0,
            "details": [f"[!] Failed to read PCAP: {e}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_summary_summary": {}
        }

    scan_ports = defaultdict(set)
    alerts = []
    log_entries = []
    suspicious_ips = set()

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]

            if tcp.flags == 'S':  # SYN packet
                scan_ports[ip.src].add(tcp.dport)
                log_entries.append({
                    "time": datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "protocol": "TCP",
                    "length": len(pkt),
                    "info": f"SYN to port {tcp.dport}"
                })

    for src, ports in scan_ports.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            suspicious_ips.add(src)
            alerts.append(f"[!] Port Scan: {src} scanned {len(ports)} ports")

    # === Threat Hunting Info ===
    try:
        with open(enrich_json_path, "r") as f:
            enrich_data = json.load(f)
            all_ips_data = enrich_data.get("ips", {})
    except Exception as e:
        all_ips_data = {}

    threat_hunting_info = {}
    for ip in suspicious_ips:
        threat_hunting_info[ip] = all_ips_data.get(ip, {
            "ip": ip,
            "abuse_confidence_score": "N/A",
            "total_reports": "N/A",
            "country_code": "N/A",
            "domain": "N/A",
            "hostnames": [],
            "last_reported_at": "N/A"
        })

    # === Groq-formatted summaries ===
    threat_hunting_raw = refine_threat_intel(threat_hunting_info)
    threat_hunting_summary = ""
    for ip, summary in threat_hunting_raw.items():
       threat_hunting_summary += f"<div class='mb-4'><strong>{ip}</strong><br>{summary}</div><br>"


    # === AI Summary ===
    if alerts:
        summary = generate_dynamic_summary(
            "Port Scanning",
            list(suspicious_ips),
            macs=[],
            packet_count=len(log_entries)
        )
    else:
        summary = "No port scanning activity detected."

    return {
        "category": "Port Scanning",
        "count": len(alerts),
        "details": alerts,
        "unique_ips": list(suspicious_ips),
        "mac_addresses": [],
        "total_packets": len(log_entries),
        "log_entries": log_entries,
        "summary": summary,
        "threat_hunting_summary": threat_hunting_summary
    }
