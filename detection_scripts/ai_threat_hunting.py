from groq import Groq
import re

# Groq API Key
groq_api_key = "API_KEY"
client = Groq(api_key=groq_api_key)

def markdown_to_html(text):
    return re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)

def refine_threat_intel(threat_hunting_info):
    results = {}

    for ip, data in threat_hunting_info.items():
        prompt = f"""
You are a cybersecurity analyst.

Here is the enrichment data for IP address {ip}:
- Abuse Score: {data.get("abuse_confidence_score", "N/A")}
- Total Reports: {data.get("total_reports", "N/A")}
- Country: {data.get("country_code", "N/A")}
- Domain: {data.get("domain", "N/A")}
- Hostnames: {', '.join(data.get("hostnames", [])) or 'None'}
- Last Reported At: {data.get("last_reported_at", "N/A")}

Please:
1. Summarize what this IP data tells us (in plain terms).
2. Highlight anything that could indicate abuse or suspicion.
3. Suggest one or two actionable next steps.
4. All anwsers should be short
Use markdown-style formatting (**title**), be concise (< 500 characters), and avoid code blocks.
"""

        try:
            response = client.chat.completions.create(
                model="llama3-70b-8192",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,
                max_tokens=500
            )
            formatted = markdown_to_html(response.choices[0].message.content.strip())
            results[ip] = formatted

        except Exception as e:
            results[ip] = f"<strong>Error processing IP {ip}:</strong> {e}"

    return results
