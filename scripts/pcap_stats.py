import os
import datetime
from collections import Counter
from scapy.all import rdpcap, TCP, UDP, ICMP, ARP, DNS, DNSQR, IP, Ether

def analyze_pcap(file_path):
    """
    Analyze a pcap file and return various statistics as a dictionary.
    """
    result = {}

    try:
        # --- File Info ---
        file_size = os.path.getsize(file_path)
        if file_size < 1024 * 1024:
            result["file_size"] = f"{round(file_size / 1024, 2)} KB"
        else:
            result["file_size"] = f"{round(file_size / (1024 * 1024), 2)} MB"

        # --- Read Packets ---
        packets = rdpcap(file_path)
        result["total_packets"] = len(packets)

        if not packets:
            return result

        # --- Time Analysis ---
        times = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
        if times:
            capture_start = datetime.datetime.fromtimestamp(min(times), datetime.UTC)
            capture_end = datetime.datetime.fromtimestamp(max(times), datetime.UTC)
            duration = (capture_end - capture_start).total_seconds()

            result["capture_start"] = capture_start.strftime("%Y-%m-%d %H:%M:%S UTC")
            result["capture_end"] = capture_end.strftime("%Y-%m-%d %H:%M:%S UTC")
            result["duration_seconds"] = round(duration, 2)
        else:
            result["capture_start"] = result["capture_end"] = "N/A"
            result["duration_seconds"] = "N/A"

        # --- Packet Size Analysis ---
        sizes = [len(pkt) for pkt in packets]
        result["packet_size_min"] = f"{min(sizes)} Bytes"
        result["packet_size_max"] = f"{max(sizes)} Bytes"
        result["packet_size_avg"] = f"{round(sum(sizes) / len(sizes), 2)} Bytes"

        # --- Counters ---
        protocol_counter = Counter()
        port_counter = Counter()
        top_talkers_src = Counter()
        top_talkers_dst = Counter()
        mac_counter = Counter()

        dns_queries = 0
        dns_responses = 0
        http_requests = 0
        arp_requests = 0
        arp_replies = 0
        icmp_echo_req = 0
        icmp_echo_rep = 0
        tcp_syn = 0
        tcp_fin = 0
        tcp_rst = 0
        ssl_tls_counter = 0
        malformed_counter = 0

        for pkt in packets:
            if Ether in pkt:
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                mac_counter.update([src_mac, dst_mac])

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                top_talkers_src.update([src_ip])
                top_talkers_dst.update([dst_ip])

            if TCP in pkt:
                protocol_counter["TCP"] += 1
                port_counter.update([pkt[TCP].sport, pkt[TCP].dport])

                flags = pkt[TCP].flags
                if flags & 0x02:
                    tcp_syn += 1
                if flags & 0x01:
                    tcp_fin += 1
                if flags & 0x04:
                    tcp_rst += 1

            elif UDP in pkt:
                protocol_counter["UDP"] += 1
                port_counter.update([pkt[UDP].sport, pkt[UDP].dport])

            elif ICMP in pkt:
                protocol_counter["ICMP"] += 1
                if pkt[ICMP].type == 8:
                    icmp_echo_req += 1
                elif pkt[ICMP].type == 0:
                    icmp_echo_rep += 1

            elif ARP in pkt:
                protocol_counter["ARP"] += 1
                if pkt[ARP].op == 1:
                    arp_requests += 1
                elif pkt[ARP].op == 2:
                    arp_replies += 1

            if DNS in pkt:
                protocol_counter["DNS"] += 1
                if pkt.haslayer(DNSQR):
                    if pkt[DNS].qr == 0:
                        dns_queries += 1
                    else:
                        dns_responses += 1

            if pkt.haslayer("SSL") or pkt.haslayer("TLS"):
                ssl_tls_counter += 1

            if pkt.haslayer("Raw") and b'\x00' in bytes(pkt):
                malformed_counter += 1

        # --- Final Stats ---
        result.update({
            "protocol_distribution": dict(protocol_counter),
            "port_distribution": dict(port_counter.most_common(10)),
            "top_source_ips": dict(top_talkers_src.most_common(5)),
            "top_destination_ips": dict(top_talkers_dst.most_common(5)),
            "top_mac_addresses": dict(mac_counter.most_common(5)),
            "dns_queries": dns_queries,
            "dns_responses": dns_responses,
            "http_requests": http_requests,
            "arp_requests": arp_requests,
            "arp_replies": arp_replies,
            "icmp_echo_requests": icmp_echo_req,
            "icmp_echo_replies": icmp_echo_rep,
            "tcp_syn_packets": tcp_syn,
            "tcp_fin_packets": tcp_fin,
            "tcp_rst_packets": tcp_rst,
            "ssl_tls_traffic": ssl_tls_counter,
            "malformed_packets": malformed_counter
        })

    except Exception as e:
        result["error"] = f"Failed to analyze pcap: {e}"

    return result



