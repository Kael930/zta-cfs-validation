#!/usr/bin/env python3
import argparse, hashlib, hmac, os, socket, struct, time

CLS_LOS_FLOOD        = 11
CLS_AOS_RECOVERY     = 12
CLS_LOS_BURST_BENIGN = 13

def build_packet(key, msg_id, role, src_id, pkt_class, los_state, seq_num, expiry, run_id):
    ccsds = struct.pack(">HHH6s", msg_id, 0xC000, 5, b"\x00" * 6)
    meta  = struct.pack(">BBBBQII", role, src_id, pkt_class, los_state, seq_num, expiry, run_id)
    hdr32 = ccsds + meta
    mac   = hmac.new(key, hdr32, hashlib.sha256).digest()
    return hdr32 + mac

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    key = os.environ.get("ZTA_HMAC_KEY", "ZTA_TESTBED_DEFAULT_KEY_CHANGE_ME").encode("utf-8")[:64]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = {1: 1, 5: 1, 10: 1, 11: 1, 12: 1, 13: 1}

    def send(pkt, delay=0.04):
        sock.sendto(pkt, (args.host, args.port))
        time.sleep(delay)

    burst_map = [(10, 3), (11, 5), (12, 8), (13, 12)]

    for run_id in range(1, args.runs + 1):
        now = int(time.time())
        send(build_packet(key, 0x1880, 0x01, 1, CLS_AOS_RECOVERY, 0, seq[1], now + 3600, run_id), 0.05)
        seq[1] += 1

        for sid, bsize in burst_map:
            for _ in range(bsize):
                send(build_packet(key, 0x1880, 0x01, sid, CLS_LOS_BURST_BENIGN, 1, seq[sid], now + 3600, run_id), 0.04)
                seq[sid] += 1

        for _ in range(200):
            send(build_packet(key, 0x1880, 0x01, 5, CLS_LOS_FLOOD, 1, seq[5], now + 3600, run_id), 0.04)
            seq[5] += 1

        now = int(time.time())
        send(build_packet(key, 0x1880, 0x01, 1, CLS_AOS_RECOVERY, 0, seq[1], now + 3600, run_id), 0.05)
        seq[1] += 1
        for _ in range(10):
            send(build_packet(key, 0x1880, 0x01, 5, CLS_AOS_RECOVERY, 0, seq[5], now + 3600, run_id), 0.04)
            seq[5] += 1
        for _ in range(10):
            send(build_packet(key, 0x1880, 0x01, 13, CLS_AOS_RECOVERY, 0, seq[13], now + 3600, run_id), 0.04)
            seq[13] += 1

        print(f"[+] Burst/Recovery Run {run_id}/{args.runs} done.")

    sock.close()

if __name__ == "__main__":
    main()
