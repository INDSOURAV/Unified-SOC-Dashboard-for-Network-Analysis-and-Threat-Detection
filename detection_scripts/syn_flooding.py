from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from detection_scripts.ai_summary import generate_dynamic_summary
from datetime import datetime
from detection_scripts.ai_threat_hunting import refine_threat_intel  # NEW import
import json

# === Threshold ===
SYN_FLOOD_THRESHOLD = 100  # SYN packets from a single IP

def detect_syn_flooding(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {
            "category": "SYN Flood",
            "count": 0,
            "details": [f"[!] Failed to read PCAP: {e}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_hunting_summary": ""
        }

    syn_count = defaultdict(int)
    alerts = []
    log_entries = []
    suspicious_ips = set()

    # === SYN Flood detection logic ===
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]

            if tcp.flags == 'S':  # SYN only
                syn_count[ip.src] += 1
                log_entries.append({
                    "time": datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "protocol": "TCP",
                    "length": len(pkt),
                    "info": f"SYN to port {tcp.dport}"
                })

    # Check for SYN flood alert condition
    for src, count in syn_count.items():
        if count > SYN_FLOOD_THRESHOLD:
            suspicious_ips.add(src)
            alerts.append(f"[!] SYN Flood: {src} sent {count} SYN packets")

    # === Threat Intelligence Enrichment ===
    try:
        with open(enrich_json_path, "r") as f:
            enrich_data = json.load(f)
            all_ips_data = enrich_data.get("ips", {})
    except Exception:
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

    threat_hunting_raw = refine_threat_intel(threat_hunting_info)
    threat_hunting_summary = ""
    for ip, summary in threat_hunting_raw.items():
        threat_hunting_summary += f"<div class='mb-4'><strong>{ip}</strong><br>{summary}</div><br>"

    # === AI Summary if alerts exist ===
    if alerts:
        summary = generate_dynamic_summary(
            "SYN Flooding",
            list(suspicious_ips),
            macs=[],  # MACs not relevant for SYN flooding
            packet_count=len(log_entries)
        )
    else:
        summary = "No SYN flood activity detected."

    return {
        "category": "SYN Flood",
        "count": len(alerts),
        "details": alerts,
        "unique_ips": list(suspicious_ips),
        "mac_addresses": [],
        "total_packets": len(log_entries),
        "log_entries": log_entries,
        "summary": summary,
        "threat_hunting_summary": threat_hunting_summary
    }
