from scapy.all import rdpcap

def extract_credentials(pcap_file):
    packets = rdpcap(pcap_file)
    credentials = []
    seen_payloads = set()

    for pkt in packets:
        if pkt.haslayer('Raw'):
            payload = pkt['Raw'].load

            # Avoid duplicates
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)

            source_ip = pkt[0][1].src
            dest_ip = pkt[0][1].dst

            # HTTP Basic Auth
            if b'Authorization:' in payload:
                try:
                    auth_data = payload.split(b'Authorization: Basic ')[1].split(b'\r\n')[0]
                    # It's Base64 encoded usually, but sometimes might be in plain
                    try:
                        import base64
                        decoded = base64.b64decode(auth_data).decode('utf-8')
                        credentials.append({
                            'protocol': 'HTTP Basic Auth',
                            'src_ip': source_ip,
                            'dst_ip': dest_ip,
                            'data': decoded
                        })
                    except Exception:
                        # If Base64 decoding fails, fallback to raw
                        credentials.append({
                            'protocol': 'HTTP Basic Auth',
                            'src_ip': source_ip,
                            'dst_ip': dest_ip,
                            'data': auth_data.decode('utf-8', errors='ignore')
                        })
                except Exception:
                    pass

            # FTP Login
            elif b'USER' in payload or b'PASS' in payload:
                try:
                    line = payload.decode('utf-8', errors='ignore')
                    if 'USER' in line:
                        user = line.strip()
                        credentials.append({
                            'protocol': 'FTP',
                            'src_ip': source_ip,
                            'dst_ip': dest_ip,
                            'data': user
                        })
                    elif 'PASS' in line:
                        password = line.strip()
                        credentials.append({
                            'protocol': 'FTP',
                            'src_ip': source_ip,
                            'dst_ip': dest_ip,
                            'data': password
                        })
                except Exception:
                    pass

            # IMAP/POP3 LOGIN
            elif b'LOGIN' in payload:
                try:
                    line = payload.decode('utf-8', errors='ignore')
                    if 'LOGIN' in line:
                        login_info = line.strip()
                        credentials.append({
                            'protocol': 'IMAP/POP3',
                            'src_ip': source_ip,
                            'dst_ip': dest_ip,
                            'data': login_info
                        })
                except Exception:
                    pass

    return {
        'total_credentials_found': len(credentials),
        'credentials': credentials
    }


