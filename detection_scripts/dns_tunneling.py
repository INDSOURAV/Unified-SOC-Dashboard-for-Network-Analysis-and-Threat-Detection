from subprocess import check_output, CalledProcessError
from detection_scripts.ai_summary import generate_dynamic_summary
from detection_scripts.ai_threat_hunting import refine_threat_intel
import json
from datetime import datetime

def detect_dns_tunneling(pcap_file, enrich_json_path="uploads/enriched_output.json"):
    alerts = []
    log_entries = []
    suspicious_ips = set()

    try:
        # === Large DNS packets > 512 bytes ===
        large_dns_output = check_output([
            "tshark", "-r", pcap_file, "-Y", "dns && udp.length > 512",
            "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "dns.qry.name", "-e", "udp.length"
        ], text=True)

        for line in large_dns_output.strip().splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 4:
                epoch, src_ip, query_name, length = parts
                suspicious_ips.add(src_ip)
                alerts.append(f"[!] Large DNS packet: Source IP {src_ip} with query {query_name} and length {length} bytes")
                log_entries.append({
                    "time": datetime.utcfromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": "--",
                    "protocol": "DNS",
                    "length": length,
                    "info": f"Large DNS query: {query_name}"
                })

        # === Suspicious or long queries ===
        suspicious_dns_output = check_output([
            "tshark", "-r", pcap_file, "-Y", "dns.qry.name",
            "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "dns.qry.name"
        ], text=True)

        for line in suspicious_dns_output.strip().splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 3:
                epoch, src_ip, query_name = parts
                if len(query_name) > 60 or any(keyword in query_name.lower() for keyword in ["dnscat", "exfil", "tunnel", "cmd"]):
                    suspicious_ips.add(src_ip)
                    alerts.append(f"[!] Suspicious DNS query from {src_ip}: {query_name}")
                    log_entries.append({
                        "time": datetime.utcfromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": "--",
                        "protocol": "DNS",
                        "length": len(query_name),
                        "info": f"Suspicious DNS query: {query_name}"
                    })

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
                "DNS Tunneling",
                list(suspicious_ips),
                macs=[],
                packet_count=len(log_entries)
            )
        else:
            summary = "No DNS tunneling behavior detected."

        return {
            "category": "DNS Tunneling",
            "count": len(alerts),
            "details": alerts,
            "unique_ips": list(suspicious_ips),
            "mac_addresses": [],
            "total_packets": len(log_entries),
            "log_entries": log_entries,
            "summary": summary,
            "threat_hunting_summary": threat_hunting_summary
        }

    except CalledProcessError as e:
        return {
            "category": "DNS Tunneling",
            "count": 0,
            "details": [f"[!] Error processing PCAP: {str(e)}"],
            "unique_ips": [],
            "mac_addresses": [],
            "total_packets": 0,
            "log_entries": [],
            "summary": "Error generating summary.",
            "threat_hunting_summary": ""
        }
