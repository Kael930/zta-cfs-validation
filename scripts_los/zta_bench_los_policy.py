#!/usr/bin/env python3
import argparse, hashlib, hmac, os, socket, struct, time

CLS_WARMUP             = 0
CLS_AOS_BENIGN         = 6
CLS_AOS_UNAUTH         = 7
CLS_LOS_BENIGN_VALID   = 8
CLS_LOS_BENIGN_EXPIRED = 9
CLS_LOS_UNAUTH         = 10
CLS_LOS_FLOOD          = 11
CLS_AOS_RECOVERY       = 12

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
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--rate", type=float, default=20.0)
    args = ap.parse_args()

    key = os.environ.get("ZTA_HMAC_KEY", "ZTA_TESTBED_DEFAULT_KEY_CHANGE_ME").encode("utf-8")[:64]
    interval = 1.0 / args.rate
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = {1: 1, 2: 1, 3: 1, 5: 1}

    def send_pkt(pkt):
        sock.sendto(pkt, (args.host, args.port))
        time.sleep(interval)

    now = int(time.time())
    print(f"[*] Warm-up: 50 packets @ {args.rate} pkt/s...")
    for _ in range(50):
        send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_WARMUP, 0, seq[1], now + 3600, 0))
        seq[1] += 1

    for run_id in range(1, args.runs + 1):
        now = int(time.time())
        t0 = time.time()

        # Phase 1: AOS-1
        for i in range(20):
            last_valid_seq = seq[1]
            send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_AOS_BENIGN, 0, seq[1], now + 3600, run_id))
            seq[1] += 1
            if i % 2 == 0:
                send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_AOS_UNAUTH, 0, last_valid_seq, now + 3600, run_id))
            else:
                send_pkt(build_packet(key, 0x1880, 0x02, 3, CLS_AOS_UNAUTH, 0, seq[3], now + 3600, run_id))
                seq[3] += 1

        # Phase 2: LOS (400 pkts/run)
        for _ in range(50):
            now = int(time.time())
            last_valid_seq = seq[1]
            send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_LOS_BENIGN_VALID, 1, seq[1], now + 3600, run_id))
            seq[1] += 1
            send_pkt(build_packet(key, 0x1880, 0x01, 2, CLS_LOS_BENIGN_EXPIRED, 1, seq[2], now - 120, run_id))
            seq[2] += 1
            send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_LOS_UNAUTH, 1, last_valid_seq, now + 3600, run_id))
            send_pkt(build_packet(key, 0x1880, 0x02, 3, CLS_LOS_UNAUTH, 1, seq[3], now + 3600, run_id))
            seq[3] += 1
            for _ in range(4):
                send_pkt(build_packet(key, 0x1880, 0x01, 5, CLS_LOS_FLOOD, 1, seq[5], now + 3600, run_id))
                seq[5] += 1

        # Phase 3: AOS-2 Recovery
        now = int(time.time())
        for _ in range(50):
            send_pkt(build_packet(key, 0x1880, 0x01, 1, CLS_AOS_RECOVERY, 0, seq[1], now + 3600, run_id))
            seq[1] += 1
        for _ in range(10):
            send_pkt(build_packet(key, 0x1880, 0x01, 5, CLS_AOS_RECOVERY, 0, seq[5], now + 3600, run_id))
            seq[5] += 1

        print(f"[+] Run {run_id:2d}/{args.runs} completed in {time.time() - t0:.1f}s")

    sock.close()
    print("[*] Experiment A finished.")

if __name__ == "__main__":
    main()
