#!/usr/bin/env python3
"""
capture_v3.py - CICIoMT2024-aligned feature extractor for Raspberry Pi

Key improvements:
 - Rate: packets per second
 - psh_flag_number: ratio (psh_packets / total_packets)
 - ack/syn/rst counts: integer counts
 - Protocol fields: normalized fractions
 - IAT: mean inter-arrival time in seconds (<1 for normal traffic)
"""

import time
import traceback
import requests
import pyshark
from statistics import stdev
from collections import defaultdict
import math
import threading
import json
import ipaddress
import subprocess
import logging
import time

# These IPs will NEVER be blocked
WHITELIST = {
    "127.0.0.1",
    "localhost",
    "192.168.0.1",      # Example network
    "192.168.0.101",      # Example network
    "192.168.0.102",      # Example network
    "192.168.137.127",   # Your Pi (REPLACE THIS with Pi’s real IP)
    "192.168.137.1", 
    "fe80::2ff:c292:76f1:1b22"  # Your Pi (REPLACE THIS with Pi’s real IP)
}



# ---------------- CONFIGURATION ---------------- #
INTERFACE = 'eth0'
WINDOW_SECONDS = 3
BACKEND_URL1 = 'http://192.168.0.101:8000/predict'
BACKEND_URL2 = 'http://192.168.0.101:8000/predict_batch'
SEND_BATCH = True
# ------------------------------------------------ #

FEATURE_ORDER = [
    "Time_To_Live", "Rate", "psh_flag_number", "ack_count", "syn_count", "rst_count",
    "DNS", "TCP", "UDP", "ARP", "ICMP", "IPv", "Std", "Tot size", "IAT"
]

# Create a logger (optional but recommended)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("capture_v3")

# Internal record of blocked IPs
blocked_ips = {}
blocked_lock = threading.Lock()

# Name of ipset set (must exist beforehand)
IPSET_NAME = "blocked_ips"

def safe_div(a, b, fallback=0.0):
    return a / b if b else fallback

def is_valid_ip(ip):
    """Returns True if ip is valid IPv4 or IPv6."""
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def add_block(ip):
    """
    Add IP to ipset safely unless it is whitelisted.
    """

    # ------------------------------
    # ✅ DO NOT BLOCK WHITELISTED IPS
    # ------------------------------
    if ip in WHITELIST:
        logger.warning(f"[BLOCK] Skipping whitelisted IP: {ip}")
        return False

    # ------------------------------
    # ✅ DO NOT BLOCK INVALID IPS
    # ------------------------------
    if not is_valid_ip(ip):
        logger.warning(f"[BLOCK] Ignoring invalid IP: {ip}")
        return False

    ts = int(time.time())

    # ------------------------------
    # ✅ CHECK ALREADY BLOCKED
    # ------------------------------
    with blocked_lock:
        if ip in blocked_ips:
            logger.info(f"[BLOCK] IP already blocked: {ip}")
            return False
        blocked_ips[ip] = ts

    # ------------------------------
    # ✅ ADD TO IPSET
    # ------------------------------
    try:
        result = subprocess.run(
            ["sudo", "ipset", "add", IPSET_NAME, ip, "-exist"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"[BLOCK] ipset error for {ip}: {result.stderr}")
            return False

        logger.info(f"[BLOCK] ✅ BLOCKED {ip} at {ts}")
        return True

    except Exception as e:
        logger.error(f"[BLOCK] Exception blocking {ip}: {e}")
        return False


def send_to_backend(batch):
    """
    Robust POST handler:
       ✅ Validates server response
       ✅ Extracts 'attack' safely
       ✅ Calls add_block(ip) for each attacker
       ✅ Logs everything
       ✅ Survives malformed JSON
    """

    if not SEND_BATCH:
        logger.info("[SEND] SEND_BATCH=False, skipping")
        return

    if not batch:
        logger.info("[SEND] Empty batch, nothing to send")
        return

    try:
        r = requests.post(BACKEND_URL2, json=batch, timeout=10)
        logger.info(f"[SEND] /predict_batch -> {r.status_code}")

        # log full response text
        logger.info(f"[SEND] Response: {r.text}")

        if r.status_code != 200:
            logger.error(f"[SEND] Backend returned error code {r.status_code}")
            return

        # JSON parsing
        try:
            response = r.json()
        except Exception:
            logger.error("[SEND] Failed to parse JSON from backend")
            return

        attack_ips = response.get("attack", [])
        if not isinstance(attack_ips, list):
            logger.error("[SEND] 'attack' field not a list")
            return

        for ip in attack_ips:
            if not isinstance(ip, str):
                logger.warning(f"[SEND] Skipping non-string IP: {ip}")
                continue
            add_block(ip.strip())

    except Exception as e:
        logger.error(f"[SEND] Exception during backend POST: {e}")


def compute_window_features(bucket):
    sizes = bucket['sizes']
    ts = bucket['ts']
    ttls = bucket['ttls']
    count = len(sizes)
    if count == 0:
        return None

    # Duration (seconds)
    duration_s = max(ts[-1] - ts[0], 1e-9)

    # --- Core metrics ---
    tot_size = sum(sizes)
    rate = count / duration_s  # packets per second

    # --- Std of packet sizes ---
    if count > 1:
        try:
            std_size = float(stdev(sizes))
        except Exception:
            mean_s = sum(sizes) / count
            var = sum((x - mean_s) ** 2 for x in sizes) / count
            std_size = math.sqrt(var)
    else:
        std_size = 0.0

    # --- IAT (mean inter-arrival time in seconds) ---
    if count > 1:
        diffs = [ts[i] - ts[i-1] for i in range(1, count)]
        pos_diffs = [d for d in diffs if d > 0]
        iat_seconds = sum(pos_diffs) / len(pos_diffs) if pos_diffs else sum(diffs) / len(diffs)
    else:
        iat_seconds = 0.0

    # --- TTL average ---
    ttl_avg = safe_div(sum(ttls), len(ttls)) if ttls else 0.0

    # --- Flags ---
    psh_frac = safe_div(bucket['psh_count'], count)
    ack_count = bucket['ack_count']
    syn_count = bucket['syn_count']
    rst_count = bucket['rst_count']

    # --- Protocol fractions ---
    DNS_frac = safe_div(bucket['dns_seen_count'], count)
    TCP_frac = safe_div(bucket['tcp_seen_count'], count)
    UDP_frac = safe_div(bucket['udp_seen_count'], count)
    ARP_frac = safe_div(bucket['arp_seen_count'], count)
    ICMP_frac = safe_div(bucket['icmp_seen_count'], count)
    IPv_frac = safe_div(bucket['ipv_seen_count'], count)

    feat = {
        "Time_To_Live": round(ttl_avg, 3),
        "Rate": round(rate, 6),
        "psh_flag_number": round(psh_frac, 6),
        "ack_count": int(ack_count),
        "syn_count": int(syn_count),
        "rst_count": int(rst_count),
        "DNS": round(DNS_frac, 6),
        "TCP": round(TCP_frac, 6),
        "UDP": round(UDP_frac, 6),
        "ARP": round(ARP_frac, 6),
        "ICMP": round(ICMP_frac, 6),
        "IPv": round(IPv_frac, 6),
        "Std": round(std_size, 3),
        "Tot size": int(tot_size),
        "IAT": round(iat_seconds, 9)
    }
    return feat

# def send_to_backend(batch):
#     if not SEND_BATCH:
#         print("[INFO] SEND_BATCH is False — skipping HTTP send.")
#         return
#     # try:
#     #     r1 = requests.post(BACKEND_URL1, json=batch, timeout=10)
#     #     print(f"[INFO] /predict -> {r1.status_code}, {r1.text}")
#     # except Exception as e:
#     #     print(f"[ERROR] POST {BACKEND_URL1}: {e}")
#     try:
#         r2 = requests.post(BACKEND_URL2, json=batch, timeout=10)
#         print(f"[INFO] /predict_batch -> {r2.status_code}, {r2.text}")
#         response = r2.json()
#         attack_ips = response.get('attack', [])
#         for ip in attack_ips:
#             add_block(ip)
#     except Exception as e:
#         print(f"[ERROR] POST {BACKEND_URL2}: {e}")

def live_capture():
    print(f"[*] Starting live capture on {INTERFACE} ...")
    try:
        capture = pyshark.LiveCapture(interface=INTERFACE)
    except Exception as e:
        print(f"[FATAL] LiveCapture failed: {e}")
        return

    buckets = defaultdict(lambda: {
        'sizes': [], 'ts': [], 'ttls': [],
        'psh_count': 0, 'ack_count': 0, 'syn_count': 0, 'rst_count': 0,
        'tcp_seen_count': 0, 'udp_seen_count': 0, 'dns_seen_count': 0,
        'arp_seen_count': 0, 'icmp_seen_count': 0, 'ipv_seen_count': 0
    })

    window_start = time.time()
    print(f"[INFO] Windowing: {WINDOW_SECONDS}s tumbling windows.")
    print("Live Capture Started. Press Ctrl+C to stop.")

    try:
        for packet in capture.sniff_continuously():
            try:
                now = time.time()
                src_ip = None
                ttl_val = None
                ipv_ver = None

                if 'ip' in packet:
                    src_ip = packet.ip.src
                    ttl_val = getattr(packet.ip, 'ttl', None)
                    ipv_ver = 4
                elif 'ipv6' in packet:
                    src_ip = packet.ipv6.src
                    ttl_val = getattr(packet.ipv6, 'hlim', None)
                    ipv_ver = 6

                if not src_ip:
                    src_ip = "unknown"

                pkt_len = 0
                if hasattr(packet, 'length'):
                    pkt_len = int(packet.length)
                elif hasattr(packet, 'frame_len'):
                    pkt_len = int(packet.frame_len)

                b = buckets[src_ip]
                b['sizes'].append(pkt_len)
                b['ts'].append(now)
                if ttl_val is not None:
                    b['ttls'].append(int(ttl_val))
                if ipv_ver is not None:
                    b['ipv_seen_count'] += 1

                # --- Flags ---
                if 'TCP' in packet:
                    b['tcp_seen_count'] += 1
                    tcp = packet.tcp
                    flags = str(getattr(tcp, 'flags', ''))
                    if 'P' in flags: b['psh_count'] += 1
                    if 'A' in flags: b['ack_count'] += 1
                    if 'S' in flags: b['syn_count'] += 1
                    if 'R' in flags: b['rst_count'] += 1

                if 'UDP' in packet: b['udp_seen_count'] += 1
                if 'DNS' in packet: b['dns_seen_count'] += 1
                if 'ARP' in packet: b['arp_seen_count'] += 1
                if 'ICMP' in packet or 'ICMPv6' in packet: b['icmp_seen_count'] += 1

                # --- Window flush ---
                if now - window_start >= WINDOW_SECONDS:
                    batch = []
                    for sip, bucket in list(buckets.items()):
                        feat = compute_window_features(bucket)
                        if not feat: continue
                        feat_with_ip = {"src_ip": sip}
                        for k in FEATURE_ORDER:
                            feat_with_ip[k] = feat.get(k, 0)
                        batch.append(feat_with_ip)

                    if batch:
                        print(f"[INFO] Window [{time.strftime('%H:%M:%S', time.localtime(window_start))} - {time.strftime('%H:%M:%S', time.localtime(window_start+WINDOW_SECONDS))}] -> {len(batch)} items")
                        for item in batch[:3]:
                            print(json.dumps(item, indent=2))
                        send_to_backend(batch)

                    buckets.clear()
                    window_start = now

            except KeyboardInterrupt:
                print("\n[!] Capture manually stopped.")
                break
            except Exception:
                print("[ERROR] Packet processing error:")
                traceback.print_exc()

    except KeyboardInterrupt:
        print("\n[!] Capture stopped.")
    finally:
        try:
            capture.close()
        except Exception:
            pass
        print("[INFO] Capture terminated.")

if __name__ == "__main__":
    live_capture()
