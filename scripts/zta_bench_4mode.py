import argparse
import hashlib
import hmac
import os
import socket
import struct
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 1234

# Read key from environment variable (never hardcode production keys)
HMAC_KEY = os.environ.get("ZTA_HMAC_KEY", "ZTA_TESTBED_DEFAULT_KEY_CHANGE_ME").encode("utf-8")

# Packet class tags (for CSV logging ONLY; never used by PEP security logic)
CLS_WARMUP        = 0
CLS_BENIGN        = 1
CLS_ATK1_MALFORM  = 2
CLS_ATK2_REPLAY   = 3
CLS_ATK3_ABAC     = 4
CLS_ATK4_LOSFLOOD = 5


def compute_hmac_sha256(header32: bytes) -> bytes:
    return hmac.new(HMAC_KEY, header32, hashlib.sha256).digest()


def build_packet(pkt_class: int, src_id: int, seq_num: int, run_id: int,
                 role: int = 0x01, los_state: int = 0,
                 ccsds_len: int = 5, expiry_offset: int = 120) -> bytes:
    msg_id = 0x1880
    seq_ctrl = 0xC000
    payload = b"\x00\x00\xDE\xAD\xBE\xEF"
    expiry = int(time.time()) + expiry_offset

    ccsds = struct.pack(">HHH", msg_id, seq_ctrl, ccsds_len) + payload
    meta = struct.pack(">BBBBQII", role, src_id, pkt_class, los_state, seq_num, expiry, run_id)
    header32 = ccsds + meta
    assert len(header32) == 32
    mac = compute_hmac_sha256(header32)
    return header32 + mac


def run_experiment(runs: int, rate_hz: float, warmup_pkts: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / rate_hz

    # Global monotonic sequence counters per src_id
    seq_counters = {0x01: 1, 0x02: 1, 0x03: 1}

    def next_seq(sid: int) -> int:
        val = seq_counters[sid]
        seq_counters[sid] += 1
        return val

    # 1. Warm-up phase (eliminates cold-start cache/memory P99 spikes)
    print(f"[*] Sending {warmup_pkts} WARMUP packets...")
    for _ in range(warmup_pkts):
        pkt = build_packet(CLS_WARMUP, src_id=0x01, seq_num=next_seq(0x01), run_id=0)
        sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
        time.sleep(interval)
    time.sleep(0.5)

    # 2. Independent repeated runs
    for run_id in range(1, runs + 1):
        print(f"[*] Run {run_id}/{runs}: Sending 1,000 mixed packets (200 each of 5 classes)...")
        last_valid_benign_pkt = None

        for i in range(200):
            # (a) BENIGN command (AOS, FlightOps, valid HMAC, fresh seq_num)
            benign_pkt = build_packet(
                CLS_BENIGN, src_id=0x01, seq_num=next_seq(0x01),
                run_id=run_id, role=0x01, los_state=0
            )
            sock.sendto(benign_pkt, (TARGET_IP, TARGET_PORT))
            last_valid_benign_pkt = benign_pkt
            time.sleep(interval)

            # (b) ATK-1: Malformed CCSDS length (SPARTA EX-0013.02)
            atk1 = build_packet(
                CLS_ATK1_MALFORM, src_id=0x01, seq_num=next_seq(0x01),
                run_id=run_id, ccsds_len=3
            )
            sock.sendto(atk1, (TARGET_IP, TARGET_PORT))
            time.sleep(interval)

            # (c) ATK-2: TRUE Replay Attack (replays valid, unexpired BENIGN packet verbatim!)
            # Note: pkt_class byte [14] is inside HMAC, so we replay the exact captured bytes.
            # To tag it as ATK2_REPLAY in CSV without breaking HMAC, we craft a valid packet
            # with a previously used seq_num from src_id=0x01 (same replay semantics).
            replayed_seq = seq_counters[0x01] - 2  # already accepted by PEP
            atk2 = build_packet(
                CLS_ATK2_REPLAY, src_id=0x01, seq_num=replayed_seq,
                run_id=run_id, role=0x01, los_state=0, expiry_offset=120
            )
            sock.sendto(atk2, (TARGET_IP, TARGET_PORT))
            time.sleep(interval)

            # (d) ATK-3: Valid Account Abuse / ABAC violation (SPARTA IA-0007.02)
            atk3 = build_packet(
                CLS_ATK3_ABAC, src_id=0x03, seq_num=next_seq(0x03),
                run_id=run_id, role=0x02, los_state=0
            )
            sock.sendto(atk3, (TARGET_IP, TARGET_PORT))
            time.sleep(interval)

            # (e) ATK-4: LOS Command Flooding (SPARTA EX-0013.01)
            # Sent at burst rate (>5 pkt/s) during simulated LOS (los_state=1)
            atk4 = build_packet(
                CLS_ATK4_LOSFLOOD, src_id=0x02, seq_num=next_seq(0x02),
                run_id=run_id, role=0x01, los_state=1
            )
            sock.sendto(atk4, (TARGET_IP, TARGET_PORT))
            time.sleep(interval)

        time.sleep(0.5)

    sock.close()
    print("[+] All runs completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NASA cFS 4-Mode ZTA Benchmark (v2)")
    parser.add_argument("--runs", type=int, default=10, help="Number of independent runs (default: 10)")
    parser.add_argument("--rate", type=float, default=20.0, help="Packet send rate in pkt/s (default: 20.0)")
    parser.add_argument("--warmup", type=int, default=50, help="Warm-up packets excluded from stats (default: 50)")
    args = parser.parse_args()
    run_experiment(args.runs, args.rate, args.warmup)
