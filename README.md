# NASA cFS Onboard Zero Trust PEP Validation Artifacts (`v2.1`)

Public reproducibility package for the flight-software experimental validation (**Section VII**) of:

> **A Phased Zero Trust Migration Framework for Heterogeneous Space Systems: Requirements Traceability and Model-Based Evaluation**  
> Youngjun Cho, Yooshin Kim, and Donghoon Shin (*IEEE Transactions on Aerospace and Electronic Systems*, Major Revision)

---

## 1. Overview & Testbed Environment

This repository archives the self-contained C onboard Policy Enforcement Point (`zta_pep.h`), NASA cFS `CI_LAB` integration patch, Aerospace SPARTA-derived telecommand traffic generators, LOS policy and burst-recovery benchmarks, statistical analysis scripts, and raw multi-run CSV datasets.

- **Flight Software:** NASA Core Flight System (cFS) v7.0.1 (`CI_LAB` app, intercepted inside `CI_LAB_ReadUpLink()` prior to `CFE_SB_TransmitBuffer`)
- **Host Environment:** Ubuntu 22.04.5 LTS, Intel Core i7-14700, 16 GB RAM, GCC 11.4.0
- **Cryptographic Implementation:** Self-contained FIPS 180-4 / RFC 2104 HMAC-SHA-256 with constant-time digest comparison, zero external library dependencies, and zero dynamic heap allocation in the command-processing hot path.
- **Metrics Convention:** Testbed packet-filtering results are reported as **Attack Pass Rate (APR)** and **False Positive Rate (FPR)** to remain strictly distinct from the analytical risk model's **Attack Success Rate (ASR)**.

---

## 2. 64-Byte Testbed Telecommand Frame Layout

| Byte Offset | Field | Size | Description |
| :--- | :--- | :---: | :--- |
| `0..11` | CCSDS TC Frame | 12 B | Primary header (6 B, expected `ccsds_len = 5`) + payload (6 B) |
| `12` | `role` | 1 B | Subject privilege attribute (`0x01` = FlightOps, `0x02` = LowPriv) |
| `13` | `src_id` | 1 B | Sender identifier (`0x01..0xFF`) |
| `14` | `pkt_class` | 1 B | Logging tag only (**never** used in PEP security decisions) |
| `15` | `los_state` | 1 B | Emulated onboard transceiver contact state (`0` = AOS, `1` = LOS) |
| `16..23` | `seq_num` | 8 B | Big-endian monotonic `uint64` anti-replay counter per `src_id` |
| `24..27` | `expiry` | 4 B | Big-endian `uint32` Unix token expiration timestamp |
| `28..31` | `run_id` | 4 B | Experiment repetition index for logging |
| `32..63` | `hmac` | 32 B | HMAC-SHA-256 tag computed over bytes `0..31` |

---

## 3. Summary of Experimental Results

### 3.1 Progressive Four-Mode Attenuation & Host Latency (10 Independent Runs)
- **Workload:** 50-packet warm-up excluded; 10,000 measured packets/mode at 20 pkt/s (2,000 `BENIGN` + 8,000 balanced 4-class SPARTA-derived malicious telecommands: ATK-1 `EX-0013.02`, ATK-2 `EX-0001.01`/`IA-0008.01`, ATK-3 `IA-0007.02`, ATK-4 `EX-0013.01`).
- **Observed FPR:** **0.00%** across all modes (0 falsely rejected out of 2,000 benign commands per mode).

| PEP Mode | Active Onboard Controls | Overall APR (%) | Benign Med. (µs) | ΔMed. (µs) | P95 (µs) | Mean ± Std (µs) | P99 (µs) | Early-Drop Med. (µs) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode 0:** Baseline | None onboard (Perimeter bypass) | 100.00 | 2.659 | — | 13.833 | 8.099 ± 51.951 | 57.463 | — |
| **Mode 1:** Input Val. | TE-20, TE-22 (CCSDS format check) | 75.00 | 2.814 | +0.155 | 15.533 | 7.892 ± 41.175 | 37.081 | 0.110 |
| **Mode 2:** Auth + ABAC | + TE-09, TE-04 (HMAC-SHA-256, Replay, ABAC) | 25.00 | 6.447 | +3.788 | 16.980 | 8.711 ± 18.842 | 28.593 | 3.311 |
| **Mode 3:** Auto-Isol. | + TE-15a (Generalized LOS rate quarantine, $T=5$) | **0.28** *(0.275)* | **8.828** | **+6.168** | **21.230** | **12.470 ± 24.736** | 130.652 | 3.677 |

*Per-attack APR in Mode 3: ATK-1 = 0.00%, ATK-2 = 0.00%, ATK-3 = 0.00%, ATK-4 = 1.10% (22/2,000 initial window packets prior to quarantine trigger).*

---

### 3.2 Static Code & Memory Footprint (`ci_lab.so`, GNU `size`/`nm`)

| Mode | `.text` (B) | `.data` (B) | `.bss` (B) | Total (B) | Δ`.text` (B) | ΔTotal |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode 0 (Baseline)** | 12,984 | 936 | 160 | 14,080 | — | — |
| **Mode 1 (Input Val.)** | 13,102 | 936 | 160 | 14,198 | +118 | +118 B (+0.12 KiB) |
| **Mode 2 (Auth + ABAC)** | 17,962 | 960 | 6,416 | 25,338 | +4,978 | +11,258 B (+10.99 KiB) |
| **Mode 3 (Auto-Isol.)** | 18,423 | 960 | 10,512 | 29,895 | +5,439 | +15,815 B (+15.44 KiB) |

*Static state tables in Mode 3 total 10,240 B (`zta_replay_tbl`: 6,144 B / 6.00 KiB; `zta_rate_tbl`: 4,096 B / 4.00 KiB).*

---

### 3.3 Experiment A: Comparative LOS Policy Enforcement (10 AOS–LOS–AOS Cycles)
- **Workload:** 5,000 measured packets/policy at 20 pkt/s (50-packet warm-up excluded): 200 AOS benign, 200 AOS unauth, 500 LOS valid benign, 500 LOS expired benign, 1,000 LOS unauth (500 replay + 500 ABAC), 2,000 LOS flood, and 600 AOS recovery commands.

| LOS Policy Architecture | Env Flag | AOS Benign Pass | LOS Valid Pass | LOS Expired Reject | LOS Unauth Pass | LOS Flood Pass | AOS Recovery | LOS Valid Med. (µs) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Ground-Dependent Fail-Closed** | `ZTA_LOS_POLICY=0` | 100.00% | **0.00%** | 100.00% | 0.00% | 0.00% | 100.00% | 0.031 *(early-drop)* |
| **Ground-Dependent Fail-Open** | `ZTA_LOS_POLICY=1` | 100.00% | 100.00% | **0.00%** | **100.00%** | **100.00%** | 100.00% | 1.923 |
| **Proposed Hybrid ZTA ($T=5$)** | `ZTA_LOS_POLICY=2` | **100.00%** | **100.00%** | **100.00%** | **0.00%** | **2.50%** | **100.00%** | **14.242** |

---

### 3.4 Experiment B-2: Benign Burst Sensitivity & Post-Quarantine AOS Recovery (5 Runs per $T$)

| Threshold $T$ (pkt/s) | $B=3$ Pass | $B=5$ Pass | $B=8$ Pass | $B=12$ Pass | ATK-4 Flood Pass (1,000) | AOS Recovery |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **5** | 100.00% | 100.00% | 62.50% *(15/40 blocked)* | 41.67% *(35/60 blocked)* | 2.50% *(25/1,000)* | 100.00% |
| **10** | 100.00% | 100.00% | 100.00% | 83.33% *(10/60 blocked)* | 5.00% *(50/1,000)* | 100.00% |
| **20** | 100.00% | 100.00% | 100.00% | 100.00% | 10.00% *(100/1,000)* | 100.00% |

---

## 4. Repository Structure

```text
zta-cfs-validation/
├── src/
│   └── zta_pep.h                         # Self-contained onboard PEP (HMAC-SHA-256, Replay, ABAC, TE-15a, LOS policies)
├── patches/
│   └── ci_lab_zta.patch                  # NASA cFS v7.0.1 CI_LAB integration patch
├── scripts_los/
│   ├── zta_bench_los_policy.py           # Experiment A: AOS-LOS-AOS 3-policy traffic generator
│   ├── zta_bench_burst_recovery.py       # Experiment B-2: Benign burst & AOS quarantine recovery generator
│   └── analyze_los_burst.py              # Aggregator for Experiment A & B-2 CSV datasets
├── data_los/
│   ├── los_policy0_failclosed.csv        # Raw 10-run CSV (Fail-Closed)
│   ├── los_policy1_failopen.csv          # Raw 10-run CSV (Fail-Open)
│   ├── los_policy2_hybrid.csv            # Raw 10-run CSV (Proposed Hybrid ZTA)
│   ├── burst_T5.csv                      # Raw 5-run burst/recovery CSV (T=5)
│   ├── burst_T10.csv                     # Raw 5-run burst/recovery CSV (T=10)
│   └── burst_T20.csv                     # Raw 5-run burst/recovery CSV (T=20)
└── README.md
```
*(Original 4-mode v2 benchmark scripts and 10-run CSV datasets remain archived alongside the `v2.1` additions.)*

---

## 5. Reproduction Instructions

### 5.1 Build & Static Footprint Measurement
```bash
# Copy header & apply patch inside NASA cFS v7.0.1 root ($CFS_ROOT)
cp src/zta_pep.h "$CFS_ROOT/apps/ci_lab/fsw/src/zta_pep.h"
cd "$CFS_ROOT/apps/ci_lab" && git apply ~/zta-cfs-validation/patches/ci_lab_zta.patch

# Measure Mode 0..3 binary/static memory footprint
cd "$CFS_ROOT"
for MODE in 0 1 2 3; do
  sed -i "s/#define ZTA_PHASE_MODE .*/#define ZTA_PHASE_MODE $MODE/" apps/ci_lab/fsw/src/ci_lab_app.c
  make -j$(nproc) && make install
  size build/exe/cpu1/cf/ci_lab.so
  nm --size-sort -S build/exe/cpu1/cf/ci_lab.so | grep zta
done
```

### 5.2 Run Experiment A (LOS Policy Comparison) & Experiment B-2 (Burst/Recovery)
With `ZTA_PHASE_MODE` built as `3`, launch cFS (`./core-cpu1` in `$CFS_ROOT/build/exe/cpu1`) with the desired policy/threshold environment variables:

```bash
# Terminal 1 (cFS) — example for Hybrid ZTA (Policy 2, T=5)
export ZTA_HMAC_KEY="TAES_ZTA_TEST_KEY_2026"
export ZTA_LOS_POLICY=2          # 0=Fail-Closed, 1=Fail-Open, 2=Hybrid ZTA
export ZTA_LOS_MAX_PKTS=5        # 5, 10, or 20 for Experiment B-2
export ZTA_CSV_FILE="$HOME/zta-cfs-validation/data_los/los_policy2_hybrid.csv"
./core-cpu1

# Terminal 2 (Traffic Generator)
export ZTA_HMAC_KEY="TAES_ZTA_TEST_KEY_2026"
python3 ~/zta-cfs-validation/scripts_los/zta_bench_los_policy.py --runs 10 --rate 20
# or for Experiment B-2:
python3 ~/zta-cfs-validation/scripts_los/zta_bench_burst_recovery.py --runs 5

# Aggregate all Experiment A & B-2 metrics
python3 ~/zta-cfs-validation/scripts_los/analyze_los_burst.py
```

---

## 6. Release History
- **`v2.1` (Current):** Added Experiment A (3-policy LOS comparison), Experiment B-2 (benign burst tolerance & authenticated AOS recovery), Mode 0–3 static ELF footprint measurements, and updated `zta_pep.h` with runtime `ZTA_LOS_POLICY` / `ZTA_LOS_MAX_PKTS` configuration.
- **`v2.0`:** 10-run progressive 4-mode benchmark with self-contained HMAC-SHA-256, 64-bit sliding-window anti-replay, ABAC, and generalized LOS rate quarantine.
