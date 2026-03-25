import time
import requests
import json
from datetime import datetime, timezone
from siem_core.config import ES_HOST, MODSEC_INDEX, NORMALIZED_INDEX, CHECK_INTERVAL, BATCH_SIZE, Severity
from siem_core.processor.schema import NormalizedEvent

class ModSecNormalizer:
    def __init__(self):
        self.es_url = ES_HOST
        self.last_check = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def fetch_logs(self):
        from siem_core.config import USE_MOCK
        if USE_MOCK: return []

        query = {
            "query": {
                "range": {
                    "@timestamp": {"gt": self.last_check}
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
            "size": BATCH_SIZE
        }
        try:
            resp = requests.post(f"{self.es_url}/{MODSEC_INDEX}/_search", json=query, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("hits", {}).get("hits", [])
        except Exception as e:
            print(f"[!] Error fetching logs: {e}")
        return []

    def normalize(self, hit):
        source = hit.get("_source", {})
        txn = source.get("transaction")
        
        # Extract timestamp
        ts = source.get("@timestamp")
        
        if txn:
            # Web style (ModSec)
            messages = txn.get("messages", [])
            all_msg_text = " ".join([m.get("message", "") for m in messages])
            
            severity = Severity.INFO
            if "SQL Injection" in all_msg_text or "XSS" in all_msg_text:
                severity = Severity.HIGH
            elif "Injection" in all_msg_text:
                severity = Severity.MEDIUM

            event = NormalizedEvent(
                timestamp=ts,
                event_id=hit.get("_id"),
                category="web",
                src_ip=txn.get("client_ip", "0.0.0.0"),
                dst_ip=txn.get("host_ip", "127.0.0.1"),
                user="anonymous",
                action="blocked" if txn.get("response", {}).get("http_code", 0) >= 400 else "allowed",
                severity=severity,
                signature=messages[0].get("message", "Generic Web Attack") if messages else "Web Traffic",
                message=all_msg_text[:255],
                raw_log=json.dumps(source),
                metadata={
                    "uri": txn.get("request", {}).get("uri", ""),
                    "status": txn.get("response", {}).get("http_code", 0)
                }
            )
        else:
            # Network style (Snort/Wazuh)
            net = source.get("network", {})
            event = NormalizedEvent(
                timestamp=ts,
                event_id=hit.get("_id"),
                category="network",
                src_ip=net.get("client_ip", "0.0.0.0"),
                dst_ip=net.get("dest_ip", "127.0.0.1"),
                user="system",
                action="alert",
                severity=Severity.HIGH if "Flood" in source.get("message", "") else Severity.CRITICAL,
                signature=source.get("message", "Network IDS Alert"),
                message=source.get("message", ""),
                raw_log=json.dumps(source),
                metadata={"source": source.get("log_source", "Snort")}
            )
        return event

    def save_normalized(self, events):
        from siem_core.config import USE_MOCK
        if USE_MOCK:
            with open("siem_events.json", "a") as f:
                for event in events:
                    f.write(json.dumps(event.to_dict()) + "\n")
            return

        for event in events:
            try:
                requests.post(f"{self.es_url}/{NORMALIZED_INDEX}/_doc/{event.event_id}", 
                              json=event.to_dict(), timeout=2)
            except Exception as e:
                print(f"[!] Error saving normalized event: {e}")

    def run(self):
        from siem_core.config import USE_MOCK
        if USE_MOCK:
            from siem_core.mock_data import generate_mock_modsec_hit
            print("[!] RUNNING IN MOCK MODE (No Docker needed)")
            while True:
                hit = generate_mock_modsec_hit()
                event = self.normalize(hit)
                self.save_normalized([event])
                print(f"[MOCK] Normalized event from {event.src_ip}")
                time.sleep(CHECK_INTERVAL)
        else:
            print(f"[*] Normalizer started. Polling {MODSEC_INDEX}...")
            while True:
                hits = self.fetch_logs()
                if hits:
                    events = [self.normalize(hit) for hit in hits]
                    self.save_normalized(events)
                    self.last_check = hits[-1]["_source"]["@timestamp"]
                    print(f"[+] Normalized {len(events)} events.")
                time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    normalizer = ModSecNormalizer()
    normalizer.run()
