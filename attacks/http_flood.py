#!/usr/bin/env python3
import argparse
import requests
import time
import threading
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
    parser = argparse.ArgumentParser(description="HTTP Flood")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    host = args.target_url.split("//")[-1].split("/")[0].split(":")[0]
    if not is_private_ip(host):
        print(f"[ERROR] Target {host} is not in the legal internal network. Access denied.")
        exit(1)

    log_dir = os.path.dirname(args.output)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(args.output, "w") as f:
        f.write("timestamp,target_url,method,status_code,error\n")

    start_time = time.time()
    interval = 1.0 / args.rate

    def worker():
        while time.time() < start_time + args.duration:
            try:
                ts = datetime.now().isoformat()
                if args.method == "POST":
                    resp = requests.post(args.target_url, data={"demo": "cs3611"}, timeout=1)
                else:
                    resp = requests.get(args.target_url, timeout=1)
                code = resp.status_code
                err = ""
            except Exception as e:
                ts = datetime.now().isoformat()
                code = 0
                err = str(e)

            with open(args.output, "a") as f:
                f.write(f"{ts},{args.target_url},{args.method},{code},\"{err}\"\n")
            time.sleep(interval)

    for _ in range(10):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    time.sleep(args.duration)

if __name__ == "__main__":
    main()
