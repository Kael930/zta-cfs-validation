import argparse
import os
import numpy as np
import pandas as pd

MODES = [
    (0, "Mode 0: Baseline (No Onboard PEP)"),
    (1, "Mode 1: Input Validation (TE-20/22)"),
    (2, "Mode 2: Auth + Anti-Replay + ABAC (TE-09/04)"),
    (3, "Mode 3: Autonomous Software Isolation (TE-15)")
]

ATK_CLASSES = ["ATK1_MALFORM", "ATK2_REPLAY", "ATK3_ABAC", "ATK4_LOS_FLOOD"]


def analyze(data_dir: str):
    base_benign_mean = None
    base_benign_med = None

    print("=== [NASA cFS ZTA Validation Summary (v2: BENIGN-Only Latency & APR)] ===\n")

    for m, label in MODES:
        csv_path = os.path.join(data_dir, f"cfs_mode{m}_v2.csv")
        if not os.path.exists(csv_path):
            print(f"[{label}] -> File not found: {csv_path}\n")
            continue

        df_all = pd.read_csv(csv_path)
        # Exclude WARMUP packets
        df = df_all[df_all["pkt_class"] != "WARMUP"].copy()

        benign = df[df["pkt_class"] == "BENIGN"]
        attacks = df[df["pkt_class"].isin(ATK_CLASSES)]

        benign_allowed = benign[benign["status"] == "ALLOWED"]
        benign_blocked = benign[benign["status"] == "BLOCKED"]
        fpr = (len(benign_blocked) / len(benign) * 100.0) if len(benign) > 0 else 0.0

        atk_passed = attacks[attacks["status"] == "ALLOWED"]
        apr = (len(atk_passed) / len(attacks) * 100.0) if len(attacks) > 0 else 0.0

        # BENIGN-only latency (apples-to-apples comparison across Mode 0..3)
        b_lat = benign_allowed["latency_us"]
        b_mean = b_lat.mean()
        b_std  = b_lat.std()
        b_med  = b_lat.median()
        b_p95  = np.percentile(b_lat, 95)
        b_p99  = np.percentile(b_lat, 99)

        if m == 0:
            base_benign_mean = b_mean
            base_benign_med  = b_med

        ov_mean = (b_mean - base_benign_mean) if base_benign_mean is not None else 0.0
        ov_med  = (b_med - base_benign_med) if base_benign_med is not None else 0.0

        n_runs = df["run_id"].nunique()
        print(f"[{label}] (Runs={n_runs}, Measured Packets={len(df)})")
        print(f"  BENIGN Availability : {len(benign_allowed)}/{len(benign)} (FPR = {fpr:.2f}%)")
        print(f"  Attack Pass Rate    : APR = {apr:.2f}% ({len(atk_passed)}/{len(attacks)} passed)")

        # Per-attack breakdown
        per_atk = []
        for ac in ATK_CLASSES:
            sub = attacks[attacks["pkt_class"] == ac]
            passed = len(sub[sub["status"] == "ALLOWED"])
            rate = (passed / len(sub) * 100.0) if len(sub) > 0 else 0.0
            per_atk.append(f"{ac}={rate:.2f}%({passed}/{len(sub)})")
        print(f"  Per-Attack APR      : " + ", ".join(per_atk))

        print(f"  BENIGN Latency (us) : Mean={b_mean:.3f} (Std={b_std:.3f}), Median={b_med:.3f}, P95={b_p95:.3f}, P99={b_p99:.3f}")
        print(f"  Overhead vs Mode 0  : Mean={ov_mean:+.3f} us, Median={ov_med:+.3f} us")

        blocked = df[df["status"] == "BLOCKED"]
        if len(blocked) > 0:
            print(f"  Early-Drop Latency  : Mean={blocked['latency_us'].mean():.3f} us, Median={blocked['latency_us'].median():.3f} us")
            print(f"  Block Reasons       : {blocked['reason'].value_counts().to_dict()}")
        print("-" * 78)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze NASA cFS ZTA v2 CSV logs")
    parser.add_argument("--data-dir", type=str, default="data", help="Directory containing cfs_mode*_v2.csv")
    args = parser.parse_args()
    analyze(args.data_dir)
