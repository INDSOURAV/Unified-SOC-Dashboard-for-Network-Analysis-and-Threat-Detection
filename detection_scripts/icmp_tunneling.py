from scapy.all import rdpcap, ICMP, IP
from collections import defaultdict
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel
import json
from datetime import datetime

ICMP_TUNNEL_PAYLOAD_THRESHOLD = 100  # bytes

def detect_icmp_tunneling(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    alerts = []
    log_entries = []
    src_ips = set()
    dst_ips = set()

    try:
        packets = rdpcap(pcap_file)

        # === Check ICMP Packets for Tunneling ===
        for pkt in packets:
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                ip = pkt[IP]
                icmp = pkt[ICMP]
                payload_size = len(icmp.payload)

                if payload_size > ICMP_TUNNEL_PAYLOAD_THRESHOLD:
                    src_ips.add(ip.src)
                    dst_ips.add(ip.dst)
                    alerts.append(f"[!] ICMP Tunneling: {ip.src} -> {ip.dst} | Payload size: {payload_size} bytes")

                    log_entries.append({
                        "time": datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": ip.src,
                        "dst_ip": ip.dst,
                        "protocol": "ICMP",
                        "length": len(pkt),
                        "info": f"Payload Size: {payload_size} bytes"
                    })

        # === Threat Hunting Info ===
        try:
            with open(enrich_json_path, "r") as f:
                enrich_data = json.load(f)
                all_ips_data = enrich_data.get("ips", {})
        except Exception:
            all_ips_data = {}

        threat_hunting_info = {}
        for ip in src_ips.union(dst_ips):
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
                "ICMP Tunneling",
                list(src_ips.union(dst_ips)),
                macs=[],
                packet_count=len(log_entries)
            )
        else:
            summary = "No suspicious ICMP tunneling behavior detected."

        return {
            "category": "ICMP Tunneling",
            "count": len(alerts),
            "details": alerts,
            "unique_ips": list(src_ips.union(dst_ips)),
            "mac_addresses": [],
            "total_packets": len(log_entries),
            "log_entries": log_entries,
            "summary": summary,
            "threat_hunting_summary": threat_hunting_summary
        }

    except Exception as e:
        return {
            "category": "ICMP Tunneling",
            "count": 0,
            "details": [f"[!] Error processing PCAP: {str(e)}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_hunting_summary": ""
        }
