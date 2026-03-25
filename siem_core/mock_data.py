import random
import time
import json
from datetime import datetime, timezone
from siem_core.processor.schema import NormalizedEvent

def generate_mock_modsec_hit():
    sources = ["WAF-ModSec", "Snort-IDS", "Wazuh-Agent"]
    ips = ["192.168.1.50", "10.0.0.15", "172.16.0.4", "8.8.8.8"]
    uri = ["/login.php", "/index.php?id=1", "/admin/config", "/api/v1/user"]
    attacks = [
        {"msg": "SQL Injection Attack Detected", "sev": "HIGH", "type": "web"},
        {"msg": "ARP Spoofing Detected", "sev": "CRITICAL", "type": "network"},
        {"msg": "Possible SYN Flood Attack", "sev": "HIGH", "type": "network"},
        {"msg": "Brute Force Attempt Locked", "sev": "HIGH", "type": "web"},
        {"msg": "Port Scanning Detected", "sev": "MEDIUM", "type": "network"}
    ]
    
    attack = random.choice(attacks)
    ip = random.choice(ips)
    source_name = random.choice(sources)
    
    if attack["type"] == "network":
        # Network style log (Snort)
        hit = {
            "_id": f"snort-{int(time.time() * 1000)}",
            "_source": {
                "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "log_source": source_name,
                "event": {"action": "alert", "category": "network"},
                "network": {"client_ip": ip, "dest_ip": "10.0.0.1"},
                "message": attack["msg"]
            }
        }
    else:
        # Web style log (ModSec)
        target = random.choice(uri)
        hit = {
            "_id": f"modsec-{int(time.time() * 1000)}",
            "_source": {
                "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "log_source": source_name,
                "transaction": {
                    "client_ip": ip,
                    "host_ip": "10.0.0.1",
                    "request": {"uri": target, "method": "GET"},
                    "response": {"http_code": 403 if random.random() > 0.5 else 200},
                    "messages": [{"message": attack["msg"]}]
                }
            }
        }
    return hit

def generate_mock_siem_event():
    hit = generate_mock_modsec_hit()
    # This function is used for direct creation, but normalizer.normalize is the main path
    return hit
