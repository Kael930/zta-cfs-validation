#!/usr/bin/env python3
import os, pandas as pd

DATA_DIR = os.path.expanduser("~/zta-cfs-validation/data_los")

print("=== [Experiment A] LOS Policy Enforcement Comparison (10 Runs) ===")
for label, fname in [
    ("Fail-Closed (P0)", "los_policy0_failclosed.csv"),
    ("Fail-Open   (P1)", "los_policy1_failopen.csv"),
    ("Hybrid ZTA  (P2)", "los_policy2_hybrid.csv"),
]:
    path = os.path.join(DATA_DIR, fname)
    if not os.path.exists(path):
        continue
    df = pd.read_csv(path)
    df = df[df["pkt_class"] != "WARMUP"]
    def rate(cls, status="ALLOWED"):
        sub = df[df["pkt_class"] == cls]
        return 100.0 * (sub["status"] == status).mean() if len(sub) else float("nan")
    print(f"{label} | N={len(df):5d} | AOS_Benign={rate('AOS_BENIGN'):6.2f}% | "
          f"LOS_Benign_Pass={rate('LOS_BENIGN_VALID'):6.2f}% | LOS_Exp_Rej={rate('LOS_BENIGN_EXPIRED','BLOCKED'):6.2f}% | "
          f"LOS_Unauth_Pass={rate('LOS_UNAUTH'):6.2f}% | LOS_Flood_Pass={rate('LOS_FLOOD'):6.2f}% | "
          f"AOS_Recov={rate('AOS_RECOVERY'):6.2f}% | "
          f"LOS_Valid_Med={df[df['pkt_class']=='LOS_BENIGN_VALID']['latency_us'].median():.3f} us")

print("\n=== [Experiment B-2] Benign Burst Sensitivity & AOS Recovery ===")
for T in [5, 10, 20]:
    path = os.path.join(DATA_DIR, f"burst_T{T}.csv")
    if not os.path.exists(path):
        continue
    df = pd.read_csv(path)
    print(f"\n--- Threshold T = {T} pkt/s ---")
    for sid, bsize in [(10, 3), (11, 5), (12, 8), (13, 12)]:
        sub = df[(df["pkt_class"] == "LOS_BURST_BENIGN") & (df["src_id"] == sid)]
        print(f"  Benign Burst B={bsize:2d} (src={sid}): Pass={100.0*(sub['status']=='ALLOWED').mean():6.2f}% "
              f"(False-Blocked={(sub['reason']=='TE15_ISOL').sum()}/{len(sub)})")
    fl = df[df["pkt_class"] == "LOS_FLOOD"]
    fl_pass = (fl["status"] == "ALLOWED").sum()
    rec = df[df["pkt_class"] == "AOS_RECOVERY"]
    print(f"  ATK-4 Flood (200/run): Passed={fl_pass}/{len(fl)} ({100.0*fl_pass/len(fl):.2f}%) | "
          f"AOS Recovery={100.0*(rec['status']=='ALLOWED').mean():.2f}%")
