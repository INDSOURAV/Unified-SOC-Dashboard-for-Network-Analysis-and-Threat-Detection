from groq import Groq
import re
from datetime import datetime

# Set your Groq API Key
groq_api_key = "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"
client = Groq(api_key=groq_api_key)

def markdown_to_html(text):
    """Convert Markdown-style bold to HTML <strong>."""
    return re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)

def generate_dynamic_summary(anomaly_name, ips, macs, packet_count):
    prompt = f"""
    You are a cybersecurity analyst.

    Anomaly Detected: {anomaly_name}
    Involved IP Addresses: {', '.join(ips)}
    Involved MAC Addresses: {', '.join(macs)}
    Number of suspicious packets: {packet_count}

    Please explain:
    - What this anomaly means
    - What is normal behavior
    - Why this behavior is suspicious
    - Recommended next steps for analysts, also do the numbering of each point
    - Your response should be less than 500 characters

    Use Markdown-style formatting for section titles (e.g., **Anomaly Explanation:**) but no code blocks.
    """

    try:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
            max_tokens=500
        )
        raw_text = response.choices[0].message.content.strip()
        return markdown_to_html(raw_text)

    except Exception as e:
        return f"<strong>Error generating summary:</strong> {e}"
