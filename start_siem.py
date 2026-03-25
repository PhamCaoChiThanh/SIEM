import subprocess
import time
import sys

def run_service(name, command):
    print(f"[*] Starting {name}...")
    return subprocess.Popen(command, shell=True)

if __name__ == "__main__":
    try:
        # Start Normalizer
        p1 = run_service("Normalizer", "python -m siem_core.processor.normalizer")
        
        # Start Correlation Engine
        p2 = run_service("Correlation Engine", "python -m siem_core.engine.correlation")
        
        # Start Dashboard
        p3 = run_service("SOC Dashboard", "python -m siem_core.web_ui.app")

        print("\n🟢 SIEM CORE IS RUNNING")
        print("🔗 Dashboard: http://localhost:5000")
        print("Press Ctrl+C to stop all services.\n")

        p1.wait()
        p2.wait()
        p3.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping SIEM services...")
        p1.terminate()
        p2.terminate()
        p3.terminate()
        sys.exit(0)
