import pandas as pd
import numpy as np

modes = [
    (0, "Mode 0 (Legacy / Ph1)"),
    (1, "Mode 1 (Ph2-A: TE-20/22)"),
    (2, "Mode 2 (Ph2-B: +TE-09/04)"),
    (3, "Mode 3 (Ph3: +TE-15)")
]

base_mean = None
base_med = None

print("=== [4-Mode Phased ZTA cFS Validation Summary] ===\n")

for m, label in modes:
    df = pd.read_csv(f"data/cfs_mode{m}.csv")
    allowed = df[df["status"] == "ALLOWED"]
    blocked = df[df["status"] == "BLOCKED"]
    
    # 200 normal + 800 attack packets sent
    atk_passed = max(0, len(allowed) - 200)
    asr = (atk_passed / 800.0) * 100.0
    
    a_mean = allowed["latency_us"].mean()
    a_std  = allowed["latency_us"].std()
    a_med  = allowed["latency_us"].median()
    a_p99  = np.percentile(allowed["latency_us"], 99)
    
    if m == 0:
        base_mean = a_mean
        base_med = a_med
        
    ov_mean = a_mean - base_mean
    ov_med  = a_med - base_med
    
    print(f"[{label}] (Total={len(df)})")
    print(f"  ALLOWED : {len(allowed)} | BLOCKED : {len(blocked)} | ASR : {asr:.2f}% ({atk_passed}/800 passed)")
    print(f"  ALLOWED Latency -> Mean: {a_mean:.3f} us (Std: {a_std:.3f}), Median: {a_med:.3f} us, P99: {a_p99:.3f} us")
    print(f"  Overhead vs Mode 0 -> Mean: {ov_mean:+.3f} us, Median: {ov_med:+.3f} us")
    if len(blocked) > 0:
        b_mean = blocked["latency_us"].mean()
        b_med  = blocked["latency_us"].median()
        print(f"  BLOCKED Latency -> Mean: {b_mean:.3f} us, Median: {b_med:.3f} us")
        counts = blocked["reason"].value_counts().to_dict()
        print(f"  Block Breakdown -> {counts}")
    print("-" * 65)
