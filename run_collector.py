import sys
import os
import time
import signal
import argparse
from app import create_app
from services.collector import WindowsSecurityCollector, SimulatedEventSource, NativeWindowsEventSource

def main():
    parser = argparse.ArgumentParser(description="PrivilegeGuard AI — Windows Security Event Log Collector")
    parser.add_argument("--channel", default="Security", help="Event log channel to monitor (default: Security)")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0)")
    parser.add_argument("--batch", type=int, default=100, help="Batch limit per polling cycle (default: 100)")
    parser.add_argument("--simulated", action="store_true", help="Run with simulated event source (no admin elevation required)")

    args = parser.parse_args()

    app = create_app()
    collector = WindowsSecurityCollector.get_instance()

    if args.simulated:
        sim_source = SimulatedEventSource()
        collector.set_event_source(sim_source, "Simulated Adapter")
        print("[*] Running in SIMULATED mode for demonstration / testing.")
    else:
        collector.set_event_source(NativeWindowsEventSource(), "Native Windows wevtapi")
        print(f"[*] Initializing native collector on channel '{args.channel}'...")

    def handle_shutdown(signum, frame):
        print("\n[*] Stopping collector gracefully...")
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    res = collector.start(app, channel=args.channel, polling_interval=args.interval, batch_size=args.batch)
    if not res.get("success"):
        print(f"[-] Failed to start collector: {res.get('error')}")
        print("[!] Note: Reading the Windows Security channel requires starting your terminal with 'Run as Administrator'.")
        sys.exit(1)

    print(f"[+] Collector successfully running on channel '{args.channel}'.")
    print(f"[+] Polling every {args.interval}s (Batch limit: {args.batch} records).")
    print(f"[+] Initial record checkpoint: #{collector.last_record_id}")
    print("[*] Press Ctrl+C to terminate collector.")

    try:
        while collector.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        handle_shutdown(None, None)

if __name__ == "__main__":
    main()
