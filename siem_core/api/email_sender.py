import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()

# Email Configuration (User needs to provide these in .env)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")

def send_email_alert(subject, message):
    if not SMTP_USER or not SMTP_PASS or not EMAIL_TO:
        print("[!] Email credentials missing. Skipping email alert.")
        return

    msg = MIMEMultipart()
    msg['From'] = f"SIEM Security Core <{SMTP_USER}>"
    msg['To'] = EMAIL_TO
    msg['Subject'] = subject

    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
            <div style="background-color: #0f172a; color: #fff; padding: 20px; text-align: center;">
                <h2 style="margin: 0; color: #38bdf8;">🚨 SECURITY INCIDENT DETECTED</h2>
            </div>
            <div style="padding: 20px;">
                {message.replace('\\n', '<br>')}
                <p style="margin-top: 20px; padding: 15px; background: #f8fafc; border-radius: 8px; font-size: 0.9em; color: #64748b;">
                    <b>Recommendation:</b> Please log in to the SOC Dashboard immediately to investigate this incident.
                </p>
            </div>
            <div style="background-color: #f1f5f9; padding: 15px; text-align: center; font-size: 0.8em; color: #94a3b8;">
                SIEM Core v1.0 | Real-time Threat Intelligence
            </div>
        </div>
    </body>
    </html>
    """
    msg.attach(MIMEText(html, 'html'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        print(f"[+] Email alert sent to {EMAIL_TO}")
    except Exception as e:
        print(f"[!] Email error: {e}")
