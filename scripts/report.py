from fpdf import FPDF
import json

class FullPCAPReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "📄 Network Insight - Full PCAP Analysis Report", ln=True, align="C")
        self.ln(10)

    def section(self, title, content, font_size=12):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, title, ln=True)
        self.set_font("Arial", "", font_size)
        if isinstance(content, dict):
            for k, v in content.items():
                self.multi_cell(0, 10, f"{k}: {v}")
        elif isinstance(content, list):
            for item in content:
                self.multi_cell(0, 10, f"- {item}")
        else:
            self.multi_cell(0, 10, str(content))
        self.ln(5)

    def section_table(self, title, data, headers=None):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, title, ln=True)
        self.set_font("Arial", "B", 12)
        if headers:
            for header in headers:
                self.cell(48, 10, header, 1)
            self.ln()
        self.set_font("Arial", "", 11)
        for row in data:
            for val in row:
                self.cell(48, 10, str(val), 1)
            self.ln()
        self.ln(5)


def create_full_report(output_path, filename, file_size, upload_time, total_packets,
                       total_endpoints, total_streams, total_files,
                       protocol_counts, alert_counts, top_alerts,
                       all_results, threat_data, extracted_credentials,
                       extracted_file_report):

    pdf = FullPCAPReport()
    pdf.add_page()

    # 1. File Info
    pdf.section("📁 File Information", {
        "Filename": filename,
        "File Size (MB)": file_size,
        "Upload Time (IST)": upload_time,
        "Total Packets": total_packets,
        "Total Endpoints": total_endpoints,
        "Total Streams": total_streams,
        "Total Files": total_files
    })

    # 2. Protocol Summary
    pdf.section("📦 Protocol Summary", protocol_counts)

    # 3. Alert Overview
    pdf.section("🚨 Alert Overview", alert_counts)

    # 4. Top 3 Alerts
    pdf.section("🔥 Top 3 Alerts", [f"{a}: {c}" for a, c in top_alerts])

    # 5. Detection Results (Summaries)
    for name, result in all_results.items():
        pdf.section(f"🧠 {name} Summary", {
            "Alert Count": result.get("count"),
            "Summary": result.get("summary")
        })

    # 6. Threat Hunting (from enriched JSON)
    if isinstance(threat_data, dict) and "ips" in threat_data:
        pdf.section("🕵️ Threat Hunting Intel", {
            ip: details.get("abuse_confidence_score", "N/A")
            for ip, details in threat_data["ips"].items()
        })

    # 7. Extracted Credentials
    if extracted_credentials:
        creds = [f"{c.get('protocol', '')}: {c.get('username', '')}/{c.get('password', '')}"
                 for c in extracted_credentials]
        pdf.section("🔑 Extracted Credentials", creds)

    # 8. Extracted Files
    if extracted_file_report:
        rows = []
        for file in extracted_file_report:
            rows.append([
                file.get("filename", "N/A"),
                file.get("type", "N/A"),
                file.get("size", "N/A")
            ])
        pdf.section_table("📂 Extracted Files", rows, headers=["Filename", "Type", "Size"])

    pdf.output(output_path)
