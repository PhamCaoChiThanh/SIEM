import time
import requests
import json
from datetime import datetime, timedelta, timezone
from siem_core.config import ES_HOST, NORMALIZED_INDEX, CHECK_INTERVAL, Severity
from siem_core.api.alert_sender import send_alert # We will create this next

class CorrelationEngine:
    def __init__(self):
        self.es_url = ES_HOST
        self.last_check = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self.state = {} # To keep track of multi-event patterns

    def fetch_events(self):
        from siem_core.config import USE_MOCK
        if USE_MOCK: return []
        
        query = {
            "query": {
                "range": {
                    "timestamp": {"gt": self.last_check}
                }
            },
            "sort": [{"timestamp": {"order": "asc"}}]
        }
        try:
            resp = requests.post(f"{self.es_url}/{NORMALIZED_INDEX}/_search", json=query, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            print(f"[!] Error fetching events: {e}")
        return []

    def check_brute_force_success(self, event_data):
        # Logic: If an IP had many 'blocked' (401/403) and then one 'allowed' (200) on /login.php
        src_ip = event_data.get("src_ip")
        uri = event_data.get("metadata", {}).get("uri", "")
        status = event_data.get("metadata", {}).get("status", 0)

        if "/login.php" in uri:
            if status >= 400:
                self.state.setdefault(src_ip, {"fails": 0, "last_fail": None})
                self.state[src_ip]["fails"] += 1
                self.state[src_ip]["last_fail"] = datetime.now()
            elif status == 200:
                if src_ip in self.state and self.state[src_ip]["fails"] >= 5:
                    # Potential Brute Force Success!
                    alert_msg = f"CRITICAL: Brute Force Success from {src_ip} on {uri}"
                    send_alert(alert_msg, Severity.CRITICAL, event_data)
                    self.state[src_ip]["fails"] = 0 # Reset

    def run(self):
        from siem_core.config import USE_MOCK
        print("[*] Correlation Engine started. Watching events...")
        
        while True:
            if USE_MOCK:
                # Read from mock file
                try:
                    with open("siem_events.json", "r") as f:
                        lines = f.readlines()
                        # Simple logic: check the last few lines
                        for line in lines[-10:]:
                            event = json.loads(line)
                            self.check_brute_force_success(event)
                            self.check_ids_alerts(event)
                except FileNotFoundError:
                    pass
            else:
                hits = self.fetch_events()
                for hit in hits:
                    event = hit.get("_source", {})
                    self.check_brute_force_success(event)
                    self.last_check = event.get("timestamp")
            
            # Cleanup old state
            now = datetime.now()
            self.state = {k: v for k, v in self.state.items() if (now - v.get("last_fail", now)) < timedelta(minutes=10)}
            
            time.sleep(CHECK_INTERVAL)

    def check_ids_alerts(self, event):
        # Trigger immediate alerts for network IDS logs (from Snort/Wazuh)
        if event.get('category') == 'network' and event.get('severity') in ['HIGH', 'CRITICAL']:
            # Avoid duplicate alerts for the same event ID in this session
            if not hasattr(self, '_sent_ids'): self._sent_ids = set()
            if event['event_id'] in self._sent_ids: return
            
            msg = f"IDS ALERT ({event.get('severity')}): {event.get('signature')} from {event.get('src_ip')}"
            send_alert(msg, event.get('severity'), event)
            self._sent_ids.add(event['event_id'])

if __name__ == "__main__":
    engine = CorrelationEngine()
    engine.run()
