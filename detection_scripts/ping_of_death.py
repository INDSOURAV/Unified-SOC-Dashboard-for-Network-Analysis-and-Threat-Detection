from scapy.all import rdpcap, ICMP, IP
from collections import defaultdict
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel
import json
from datetime import datetime

# === Thresholds ===
PING_OF_DEATH_PACKET_SIZE_THRESHOLD = 500
POD_PACKET_COUNT_THRESHOLD = 3

def detect_ping_of_death(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    alerts = []
    log_entries = []
    suspicious_ips = set()

    try:
        packets = rdpcap(pcap_file)
        pod_sources = defaultdict(int)

        # === Check ICMP for Ping of Death ===
        for pkt in packets:
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                ip = pkt[IP]
                total_packet_size = ip.len if hasattr(ip, "len") else len(pkt)

                if total_packet_size > PING_OF_DEATH_PACKET_SIZE_THRESHOLD:
                    pod_sources[ip.src] += 1
                    log_entries.append({
                        "time": datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": ip.src,
                        "dst_ip": ip.dst,
                        "protocol": "ICMP",
                        "length": total_packet_size,
                        "info": "Oversized ICMP packet"
                    })

        # === Generate Alerts ===
        for src, count in pod_sources.items():
            if count >= POD_PACKET_COUNT_THRESHOLD:
                suspicious_ips.add(src)
                alerts.append(f"[!] Ping of Death: {src} sent {count} oversized ICMP packets")

        # === Threat Hunting Info ===
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

        # === AI Summary ===
        if alerts:
            summary = generate_dynamic_summary(
                "Ping of Death",
                list(suspicious_ips),
                macs=[],
                packet_count=len(log_entries)
            )
        else:
            summary = "No Ping of Death activity detected."

        return {
            "category": "Ping of Death",
            "count": len(alerts),
            "details": alerts,
            "unique_ips": list(suspicious_ips),
            "mac_addresses": [],
            "total_packets": len(log_entries),
            "log_entries": log_entries,
            "summary": summary,
            "threat_hunting_summary": threat_hunting_summary
        }

    except Exception as e:
        return {
            "category": "Ping of Death",
            "count": 0,
            "details": [f"[!] Error processing PCAP: {str(e)}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_hunting_summary": ""
        }
