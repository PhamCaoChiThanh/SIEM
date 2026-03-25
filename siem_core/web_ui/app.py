from flask import Flask, render_template, jsonify
import requests
import json
from siem_core.config import ES_HOST

app = Flask(__name__)

ALERTS_INDEX = "siem-alerts"
EVENTS_INDEX = "siem-events"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    from siem_core.config import USE_MOCK
    if USE_MOCK:
        import os
        events, alerts, critical = 0, 0, 0
        if not os.path.exists("siem_events.json"):
            with open("siem_events.json", "w") as f: f.write("")
        if not os.path.exists("siem_alerts.json"):
            with open("siem_alerts.json", "w") as f: f.write("")

        try:
            with open("siem_events.json", "r", encoding="utf-8") as f: events = len(f.readlines())
        except: pass
        try:
            with open("siem_alerts.json", "r", encoding="utf-8") as f:
                lines = f.readlines()
                alerts = len(lines)
                for l in lines:
                    if '"severity": "CRITICAL"' in l: critical += 1
        except: pass
        return jsonify({"alerts": alerts, "events": events, "critical": critical})
    
    # Simple stats from ES
    try:
        alert_count = requests.get(f"{ES_HOST}/{ALERTS_INDEX}/_count").json().get("count", 0)
        event_count = requests.get(f"{ES_HOST}/{EVENTS_INDEX}/_count").json().get("count", 0)
        return jsonify({"alerts": alert_count, "events": event_count})
    except:
        return jsonify({"alerts": 0, "events": 0})

@app.route('/api/alerts')
def get_alerts():
    from siem_core.config import USE_MOCK
    if USE_MOCK:
        try:
            with open("siem_alerts.json", "r") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
                alerts = [json.loads(l) for l in lines[-50:]]
                return jsonify([{"_source": a} for a in reversed(alerts)])
        except Exception as e:
            print(f"DEBUG Dashboard Error: {e}")
            return jsonify([])
            
    query = {
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 50
    }
    try:
        resp = requests.post(f"{ES_HOST}/{ALERTS_INDEX}/_search", json=query).json()
        return jsonify(resp.get("hits", {}).get("hits", []))
    except:
        return jsonify([])

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
