import time
import traceback
import requests
import pyshark
from statistics import stdev
from collections import defaultdict
import math
import json
import subprocess
import threading

# ---------------- CONFIGURATION ---------------- #
INTERFACE = 'wlan0'
WINDOW_SECONDS = 3
BACKEND_URL1 = 'http://192.168.0.106:8000/predict'
BACKEND_URL2 = 'http://10.227.106.101:8000/predict_batch'
SEND_BATCH = True
IPSET_NAME = "ddos_blocklist"
# ------------------------------------------------ #

# blocked_ips: { ip: blocked_at_timestamp }
blocked_ips = {}
blocked_lock = threading.Lock()

FEATURE_ORDER = [
    "Time_To_Live", "Rate", "psh_flag_number", "ack_count", "syn_count", "rst_count",
    "DNS", "TCP", "UDP", "ARP", "ICMP", "IPv", "Std", "Tot size", "IAT"
]

def safe_div(a, b, fallback=0.0):
    return a / b if b else fallback

def add_block(ip):
    """Add IP to ipset and internal blocked list."""
    blocked_at = int(time.time())
    with blocked_lock:
        blocked_ips[ip] = blocked_at

    # Add to ipset (best-effort)
    try:
        subprocess.run(['sudo','ipset','add', IPSET_NAME, ip], check=False)
        print('Added %s to ipset %s', ip, IPSET_NAME)
    except Exception as e:
        print('Failed to add ip to ipset: %s', e)

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

def send_to_backend(batch):
    if not SEND_BATCH:
        print("[INFO] SEND_BATCH is False — skipping HTTP send.")
        return
    try:
        response = requests.post(BACKEND_URL2, json=batch, timeout=10)
        attack_ips = response['attack']
        for ip in attack_ips:
            add_block(ip)
        print(f"[INFO] /predict_batch -> {response.status_code}, {response.text}")
    except Exception as e:
        print(f"[ERROR] POST {BACKEND_URL2}: {e}")

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