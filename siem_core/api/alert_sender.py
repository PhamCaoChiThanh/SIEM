import requests
import json
from datetime import datetime, timezone
from siem_core.config import TELEGRAM_TOKEN, CHAT_ID, ES_HOST, Severity
from siem_core.api.email_sender import send_email_alert

ALERTS_INDEX = "siem-alerts"

def send_alert(message, severity, event_context=None):
    from siem_core.config import USE_MOCK
    # 1. Store Alert
    alert_doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": message,
        "severity": severity,
        "event_context": event_context,
        "status": "New"
    }
    
    if USE_MOCK:
        with open("siem_alerts.json", "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_doc) + "\n")
    else:
        try:
            requests.post(f"{ES_HOST}/{ALERTS_INDEX}/_doc", json=alert_doc, timeout=2)
        except Exception as e:
            print(f"[!] Error storing alert: {e}")

    # 2. Send to Telegram
    emoji = "🔵"
    if severity == Severity.CRITICAL: emoji = "🔴"
    elif severity == Severity.HIGH: emoji = "🟠"
    elif severity == Severity.MEDIUM: emoji = "🟡"

    tele_msg = f"{emoji} <b>SIEM ALERT: {severity}</b>\n━━━━━━━━━━━━━━━━━━\n{message}\n━━━━━━━━━━━━━━━━━━"
    
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": tele_msg, "parse_mode": "HTML"}
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"[!] Telegram error: {e}")

    # 3. Send Email Alert (For Demo 3)
    if severity in [Severity.CRITICAL, Severity.HIGH]:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source = event_context.get('metadata', {}).get('source', 'Unknown IDS') if event_context else 'SIEM Core'
        
        email_body = f"""
        <p><b>Alert level:</b> <span style="color: {'#ef4444' if severity == Severity.CRITICAL else '#f59e0b'}">{severity}</span></p>
        <p><b>Event:</b> {message}</p>
        <p><b>Source:</b> {source}</p>
        <p><b>Detection Time:</b> {timestamp}</p>
        """
        subject = f"🚨 {severity}: {message[:40]}..."
        send_email_alert(subject, email_body)
