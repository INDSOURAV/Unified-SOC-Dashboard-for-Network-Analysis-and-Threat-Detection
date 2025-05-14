from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, json
import os
import subprocess
import shutil
from fpdf import FPDF
import time
from datetime import datetime
import pytz
import sys
from collections import Counter

from detection_scripts.arp_spoofing import detect_arp_spoofing
from detection_scripts.dns_tunneling import detect_dns_tunneling
from detection_scripts.brute_force import detect_brute_force
from detection_scripts.icmp_tunneling import detect_icmp_tunneling
from detection_scripts.ping_of_death import detect_ping_of_death 
from detection_scripts.port_scanning import detect_port_scanning
from detection_scripts.syn_flooding import detect_syn_flooding

from scripts.pcap_stats import analyze_pcap
from scripts.credentials_extractor import extract_credentials
from scripts.file_processing import generate_file_extraction_report
from scripts.entity_extractor import pcap_entity_extractor
from scripts.entity_threat_detection import entity_threat_checking

def clear_folders():
    folders = ["uploads", "zeek_logs","extract_files"]
    
    for folder in folders:
        if os.path.exists(folder):
            try:
                # Use shell=True to execute the command with no confirmation required
                subprocess.run(f"rm -rf {os.path.join(folder, '*')}", shell=True, check=True)
                print(f"Cleared contents of {folder}")
            except subprocess.CalledProcessError as e:
                print(f"Error clearing {folder}: {e}")
        else:
            print(f"{folder} does not exist.")


app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
ZEEK_LOGS_FOLDER = "zeek_logs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ZEEK_LOGS_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return redirect(url_for("welcome"))

    file = request.files["file"]
    if file.filename == "":
        return redirect(url_for("welcome"))

    # Save the uploaded file
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)
    
    file_size = round(os.path.getsize(file_path) / (1024 * 1024), 2)  # Convert bytes to MB
    # Define IST timezone
    ist = pytz.timezone("Asia/Kolkata")
    # Get file modification timestamp
    upload_timestamp = os.path.getmtime(file_path)
    # Convert to UTC datetime
    utc_time = datetime.utcfromtimestamp(upload_timestamp).replace(tzinfo=pytz.utc)
    # Convert UTC to IST
    upload_time_ist = utc_time.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S")

    # Get file hash to use for caching enrichment
    enriched_file = f"uploads/enriched_output.json"

    # Run enrichment only if needed
    if not os.path.exists(enriched_file):
        print(f"[⚠️] Enrichment not done for {file.filename}. Running now...")
        extractor_result = pcap_entity_extractor(file_path)
        entity_threat_checking_result = entity_threat_checking(extractor_result)
    else:
        print(f"[✅] Reusing existing enrichment for {file.filename}")
        entity_threat_checking_result = enriched_file

    with open(entity_threat_checking_result, 'r') as f:
        threat_data = json.load(f)

    # Run tshark to extract hex data
    decoded_payloads = []
    result = subprocess.run(
    	["tshark", "-r", file_path, "-Y", "frame.len > 0", "-T", "fields", "-e", "data"],
    	stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    raw_payloads = result.stdout.strip().split("\n")
    
    # Decode each line and store
    for line in raw_payloads:
    	raw = bytes.fromhex(line.strip())
    	decoded = raw.decode("utf-8", errors="ignore").strip()
    	if decoded:
    	   decoded_payloads.append(decoded)
    	
    # Run tshark to extract protocol from each frame
    cmd = ["tshark", "-r", file_path, "-T", "fields", "-e", "_ws.col.Protocol"]
    output = subprocess.check_output(cmd, text=True)
    protocols = output.strip().splitlines()

    # Count all protocols
    proto_counts = Counter(protocols)

    # Extract selected protocols
    http_count = proto_counts.get("HTTP", 0)
    ftp_count = proto_counts.get("FTP", 0)
    ssh_count = proto_counts.get("SSH", 0)
    dns_count = proto_counts.get("DNS", 0)
    arp_count = proto_counts.get("ARP", 0)
    
    # Call of detection rules
    arp_result = detect_arp_spoofing(file_path)
    dns_result = detect_dns_tunneling(file_path)
    brute_force_result = detect_brute_force(file_path)
    icmp_tunneling_result = detect_icmp_tunneling(file_path)
    ping_of_death_result = detect_ping_of_death(file_path) 
    port_scanning_result = detect_port_scanning(file_path)
    syn_flooding_result = detect_syn_flooding(file_path)
    
    pcap_analysis = analyze_pcap(file_path)
    extract_credentials_result=extract_credentials(file_path)
    report, file_count=generate_file_extraction_report("extract_files",entity_threat_checking_result)
    try:
        # Run Zeek and Tshark commands
        subprocess.run(f"zeek -r {file_path} Log::default_logdir='{ZEEK_LOGS_FOLDER}'", shell=True, check=True)

        total_endpoints = subprocess.check_output(
            f"cat {ZEEK_LOGS_FOLDER}/conn.log | zeek-cut id.orig_h id.resp_h | sort | uniq | wc -l", shell=True, text=True
        ).strip()
        total_packets = subprocess.check_output(
            f"tshark -r {file_path} | wc -l", shell=True, text=True
        ).strip()
        total_streams = subprocess.check_output(
            f"cat {ZEEK_LOGS_FOLDER}/conn.log | wc -l", shell=True, text=True
        ).strip()
        
        total_files = "0"
        if os.path.exists(f"{ZEEK_LOGS_FOLDER}/files.log"):
            total_files = subprocess.check_output(
                f"cat {ZEEK_LOGS_FOLDER}/files.log | zeek-cut fuid | wc -l", shell=True, text=True
            ).strip()

    except subprocess.CalledProcessError:
        total_packets = total_endpoints = total_streams = total_files = "Error processing file"
        
    alert_counts = {
    "ARP Spoofing": arp_result["count"],
    "DNS Tunneling": dns_result["count"],
    "ICMP Tunneling": icmp_tunneling_result["count"],
    "Brute Force": brute_force_result["count"],
    "Ping of Death": ping_of_death_result["count"],
    "Port Scanning": port_scanning_result["count"],
    "SYN Flooding": syn_flooding_result["count"]
    }
    
    # Sort and get top 3
    top_alerts = sorted(alert_counts.items(), key=lambda x: x[1], reverse=True)[:3]


    return render_template(
        "index.html",
        pcap_file=file.filename,
        total_packets=total_packets,
        total_endpoints=total_endpoints,
        total_streams=total_streams,
        total_files=total_files,
        file_size=file_size,
        upload_time=upload_time_ist,
        HTTP_Count=http_count,
        FTP_Count=ftp_count,
        SSH_Count=ssh_count,
        DNS_Count=dns_count,
        ARP_Count=arp_count,
        decoded_payloads=decoded_payloads,
        decoded_count=len(decoded_payloads),
        arp_alerts = arp_result["details"],
	arp_alert_count = arp_result["count"],
	arp_unique_ips = arp_result["unique_ips"],
	arp_mac_addresses = arp_result["mac_addresses"],
	arp_total_packets = arp_result["total_packets"],
	arp_log_entries = arp_result["log_entries"],
	arp_alert_summary = arp_result["summary"],
	arp_threat_hunting_summary = arp_result["threat_hunting_summary"],
	
        dns_alerts=dns_result["details"],
        dns_alert_count=dns_result["count"],
        dns_alert_unique_ips = dns_result["unique_ips"],
	dns_alert_mac_addresses = dns_result["mac_addresses"],
	dns_alert_total_packets = dns_result["total_packets"],
	dns_alert_log_entries = dns_result["log_entries"],
	dns_alert_summary = dns_result["summary"],
        dns_threat_hunting_summary = dns_result["threat_hunting_summary"],
        
        brute_force_alerts=brute_force_result["details"],
        brute_force_alert_count=brute_force_result["count"],
        brute_force_unique_ips = brute_force_result["unique_ips"],
	brute_force_mac_addresses = brute_force_result["mac_addresses"],
	brute_force_total_packets = brute_force_result["total_packets"],
	brute_force_log_entries = brute_force_result["log_entries"],
	brute_force_summary = brute_force_result["summary"],
        brute_force_threat_hunting_summary = brute_force_result["threat_hunting_summary"],
        
        icmp_tunneling_alerts=icmp_tunneling_result["details"],
        icmp_tunneling_alert_count=icmp_tunneling_result["count"],
	icmp_tunneling_unique_ips = icmp_tunneling_result["unique_ips"],
	icmp_tunneling_mac_addresses = icmp_tunneling_result["mac_addresses"],
	icmp_tunneling_total_packets = icmp_tunneling_result["total_packets"],
	icmp_tunneling_log_entries = icmp_tunneling_result["log_entries"],
	icmp_tunneling_alert_summary = icmp_tunneling_result["summary"],
	icmp_tunneling_threat_hunting_summary = icmp_tunneling_result["threat_hunting_summary"],
	
        ping_of_death_alerts=ping_of_death_result["details"],
        ping_of_death_alert_count=ping_of_death_result["count"],
        ping_of_death_unique_ips = ping_of_death_result["unique_ips"],
	ping_of_death_mac_addresses = ping_of_death_result["mac_addresses"],
	ping_of_death_total_packets = ping_of_death_result["total_packets"],
	ping_of_death_log_entries = ping_of_death_result["log_entries"],
	ping_of_death_alert_summary = ping_of_death_result["summary"],
        ping_of_death_threat_hunting_summary = ping_of_death_result["threat_hunting_summary"],
        
        port_scanning_alerts=port_scanning_result["details"],
        port_scanning_alert_count=port_scanning_result["count"],
        port_scanning_unique_ips = port_scanning_result["unique_ips"],
	port_scanning_mac_addresses = port_scanning_result["mac_addresses"],
	port_scanning_total_packets = port_scanning_result["total_packets"],
	port_scanning_log_entries = port_scanning_result["log_entries"],
	port_scanning_alert_summary = port_scanning_result["summary"],
        port_scanning_threat_hunting_summary = port_scanning_result["threat_hunting_summary"],
        
        syn_flooding_alerts=syn_flooding_result["details"],
        syn_flooding_alert_count=syn_flooding_result["count"],
        syn_flooding_unique_ips = syn_flooding_result["unique_ips"],
	syn_flooding_mac_addresses = syn_flooding_result["mac_addresses"],
	syn_flooding_total_packets = syn_flooding_result["total_packets"],
	syn_flooding_log_entries = syn_flooding_result["log_entries"],
	syn_flooding_alert_summary = syn_flooding_result["summary"],
	syn_flooding_threat_hunting_summary = syn_flooding_result["threat_hunting_summary"],
        
        alert_counts=alert_counts,
    	top_alerts=top_alerts,
    	total_alerts=sum(alert_counts.values()),
    
    	total_packets_stats=pcap_analysis.get("total_packets"),
    	file_size_stats = pcap_analysis.get("file_size"),
	capture_start = pcap_analysis.get("capture_start"),
	capture_end = pcap_analysis.get("capture_end"),
	duration_seconds = pcap_analysis.get("duration_seconds"),
	packet_size_min = pcap_analysis.get("packet_size_min"),
	packet_size_max = pcap_analysis.get("packet_size_max"),
	packet_size_avg = pcap_analysis.get("packet_size_avg"),
	protocol_distribution = pcap_analysis.get("protocol_distribution"),
	top_source_ips = pcap_analysis.get("top_source_ips"),
	top_destination_ips = pcap_analysis.get("top_destination_ips"),
	top_mac_addresses = pcap_analysis.get("top_mac_addresses"),
	top_ports = pcap_analysis.get("port_distribution"),

	extracted_credentials = extract_credentials_result.get("credentials"),
	extracted_credentials_count = extract_credentials_result.get("total_credentials_found"),
	
	extracted_file_report=report,
	extracted_file_count=file_count,
	
	threat_data=threat_data
    )


if __name__ == "__main__":
    app.run(debug=True)
