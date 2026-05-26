#!/usr/bin/env python3
import argparse
import requests
import time
import csv
import os
from datetime import datetime

def is_private_ip(ip):
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 127:
            return True
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
    except:
        pass
    return False

def main():
    parser = argparse.ArgumentParser(description="Normal Traffic Generator")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    host = args.target_url.split("//")[-1].split("/")[0].split(":")[0]
    if not is_private_ip(host):
        print(f"[ERROR] Target {host} is not in the legal internal network. Access denied.")
        exit(1)

    log_dir = os.path.dirname(args.output)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(args.output, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp", "target_url", "status_code", "latency_ms", "error"])

    start = time.time()
    while time.time() - start < args.duration:
        try:
            ts = datetime.now().isoformat()
            s = time.time()
            r = requests.get(args.target_url, timeout=1)
            lat = int((time.time() - s) * 1000)
            err = ""
        except Exception as e:
            r = None
            lat = 0
            err = str(e)

        with open(args.output, "a", newline="") as f:
            csv.writer(f).writerow([ts, args.target_url, r.status_code if r else 0, lat, err])
        time.sleep(1.0 / args.rate)

if __name__ == "__main__":
    main()
