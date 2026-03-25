import requests
import time
import random

TARGET_URL = "http://localhost:80" # ModSecurity Port

def simulate_brute_force_success(ip):
    print(f"[*] Simulating Brute Force from {ip}...")
    # 6 failed attempts
    for i in range(6):
        print(f"  [-] Failed attempt {i+1}")
        requests.get(f"{TARGET_URL}/login.php?user=admin&pass=wrong", headers={"X-Forwarded-For": ip})
        time.sleep(1)
    
    # 1 successful attempt (simulated by status 200)
    print("  [+] Successful login!")
    requests.get(f"{TARGET_URL}/login.php?user=admin&pass=password123", headers={"X-Forwarded-For": ip})

def simulate_sqli(ip):
    print(f"[*] Simulating SQL Injection from {ip}...")
    payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT NULL,NULL --"
    ]
    for p in payloads:
        requests.get(f"{TARGET_URL}/index.php?id={p}", headers={"X-Forwarded-For": ip})
        time.sleep(1)

if __name__ == "__main__":
    test_ip = "192.168.1.100"
    simulate_sqli(test_ip)
    time.sleep(5)
    simulate_brute_force_success(test_ip)
