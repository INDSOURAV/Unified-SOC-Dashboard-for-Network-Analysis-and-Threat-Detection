import os
import hashlib
import json

def generate_file_extraction_report(extracted_files_folder='extract_files', threat_hunting_json_path='enriched_output.json'):
    # Load threat hunting results
    with open(threat_hunting_json_path, 'r') as f:
        threat_hunting_data = json.load(f)

    report = {
        "files": []
    }

    def calculate_sha256(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    for filename in os.listdir(extracted_files_folder):
        file_path = os.path.join(extracted_files_folder, filename)
        if os.path.isfile(file_path):
            filesize = os.path.getsize(file_path)
            sha256 = calculate_sha256(file_path)

            threat_info = threat_hunting_data.get('file_hashes', {}).get(sha256, {})
            stats = threat_info.get('analysis', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)

            threat_result = "malicious" if malicious_count > 0 else "benign"

            report["files"].append({
                "file_name": filename,
                "file_size_kb": round(filesize / 1024, 2),
                "sha256": sha256,
                "threat_result": threat_result,
                "download_path": f"../extract_files/{filename}"
            })

    file_count = len(report["files"])
    return report, file_count
