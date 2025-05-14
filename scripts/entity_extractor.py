import os
import hashlib
import subprocess
import json
from scapy.all import rdpcap, IP

EXTRACTED_FILES_DIR = 'extract_files'
os.makedirs(EXTRACTED_FILES_DIR, exist_ok=True)

def extract_files_with_zeek(pcap_path):
    command = f"sudo zeek -r {pcap_path} /usr/local/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek Log::default_logdir='zeek_logs'"
    print(f"[*] Running Zeek: {command}")
    subprocess.run(command, shell=True, check=True)

def extract_files_from_pcap():
    extracted_files = []
    file_hashes = {}

    if os.path.exists(EXTRACTED_FILES_DIR):
        for file_name in os.listdir(EXTRACTED_FILES_DIR):
            file_path = os.path.join(EXTRACTED_FILES_DIR, file_name)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    file_hashes[sha256] = file_path
                    extracted_files.append(file_path)
                    print(f"[+] Extracted: {file_path} (SHA256: {sha256})")
    else:
        print("[!] No extracted files directory found.")

    return file_hashes

def extract_ips(pcap_path):
    unique_ips = set()
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if IP in pkt:
            unique_ips.add(pkt[IP].src)
            unique_ips.add(pkt[IP].dst)
    return list(unique_ips)

def extract_domains(pcap_path):
    unique_domains = set()
    tshark_cmd = f"tshark -r {pcap_path} -Y 'dns' -T fields -e dns.qry.name"
    result = subprocess.run(tshark_cmd, shell=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.strip():
            unique_domains.add(line.strip())
    return list(unique_domains)

def pcap_entity_extractor(pcap_path):
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print("[*] Starting analysis...")
    ips = extract_ips(pcap_path)
    domains = extract_domains(pcap_path)
    extract_files_with_zeek(pcap_path)
    file_hashes = extract_files_from_pcap()

    output_data = {
        "IPs": ips,
        "Domains": domains,
        "Files": file_hashes
    }

    output_filename = f"{os.path.splitext(pcap_path)[0]}_extracted_data.json"
    with open(output_filename, 'w') as f:
        json.dump(output_data, f, indent=4)

    print(f"[✔] Analysis complete. Results saved to: {output_filename}")
    return output_filename
