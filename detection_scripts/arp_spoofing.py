from scapy.all import rdpcap, ARP
from collections import defaultdict
from datetime import datetime
import json
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel  # NEW import

# === Threshold ===
ARP_SPOOF_THRESHOLD = 3  # MAC associated with more than 3 IPs is suspicious

def detect_arp_spoofing(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {
            "category": "ARP Spoofing",
            "count": 0,
            "details": [f"[!] Failed to read PCAP: {e}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_hunting_summary": ""
        }

    ip_mac_map = defaultdict(set)
    mac_ip_map = defaultdict(set)
    alerts = []
    log_entries = []
    suspicious_ips = set()
    suspicious_macs = set()

    # First pass: build mappings
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op in (1, 2):
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            ip_mac_map[src_ip].add(src_mac)
            mac_ip_map[src_mac].add(src_ip)

    # Detect IP to multiple MACs
    for ip, macs in ip_mac_map.items():
        if len(macs) > 1:
            suspicious_ips.add(ip)
            alerts.append(f"[!] ARP Spoofing: IP {ip} maps to multiple MACs: {', '.join(macs)}")

    # Detect MAC to multiple IPs
    for mac, ips in mac_ip_map.items():
        if len(ips) > ARP_SPOOF_THRESHOLD:
            suspicious_macs.add(mac)
            alerts.append(f"[!] ARP Spoofing: MAC {mac} maps to multiple IPs: {', '.join(ips)}")

    # Collect log entries
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op in (1, 2):
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            dst_ip = pkt[ARP].pdst

            if src_mac in suspicious_macs or src_ip in suspicious_ips:
                log_entries.append({
                    "time": datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "ARP",
                    "length": len(pkt),
                    "info": f"ARP {src_ip} is-at {src_mac}"
                })

    final_macs = list(suspicious_macs)
    final_ips = list(suspicious_ips.union(*[mac_ip_map[mac] for mac in suspicious_macs]))

    # === Threat Hunting Info ===
    try:
        with open(enrich_json_path, "r") as f:
            enrich_data = json.load(f)
            all_ips_data = enrich_data.get("ips", {})
    except Exception:
        all_ips_data = {}

    threat_hunting_info = {}
    for ip in final_ips:
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
            "ARP Spoofing",
            final_ips,
            final_macs,
            len(log_entries)
        )
    else:
        summary = "No suspicious ARP activity detected."

    return {
        "category": "ARP Spoofing",
        "count": len(alerts),
        "details": alerts,
        "unique_ips": final_ips,
        "mac_addresses": final_macs,
        "total_packets": len(log_entries),
        "log_entries": log_entries,
        "summary": summary,
        "threat_hunting_summary": threat_hunting_summary
    }
