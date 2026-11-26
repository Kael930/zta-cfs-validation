# NASA cFS Onboard Zero Trust PEP Validation Artifacts (`v2.1`)

Public reproducibility package for the flight-software experimental validation (**Section VII**) of:

> **A Phased Zero Trust Migration Framework for Heterogeneous Space Systems: Requirements Traceability and Model-Based Evaluation**  
> Youngjun Cho, Yooshin Kim, and Donghoon Shin (*IEEE Transactions on Aerospace and Electronic Systems*, Major Revision)

---

## 1. Overview & Testbed Environment

This repository archives the self-contained C onboard Policy Enforcement Point (`zta_pep.h`), NASA cFS `CI_LAB` integration patch, Aerospace SPARTA-derived telecommand traffic generators, LOS policy and burst-recovery benchmarks, statistical analysis scripts, and raw multi-batch and multi-cycle CSV datasets.

- **Flight Software:** NASA Core Flight System (cFS) v7.0.1 (`CI_LAB` app, intercepted inside `CI_LAB_ReadUpLink()` prior to `CFE_SB_TransmitBuffer`)
- **Host Environment:** Ubuntu 22.04.5 LTS, Intel Core i7-14700, 16 GB RAM, GCC 11.4.0
- **Cryptographic Implementation:** Self-contained FIPS 180-4 / RFC 2104 HMAC-SHA-256 with constant-time digest comparison, zero external library dependencies, and zero dynamic heap allocation in the command-processing hot path.
- **Metrics Convention:** Testbed packet-filtering outcomes are reported directly as exact packet pass counts (`forwarded/sent`) and flooding pass rates alongside observed benign drops (**FPR**), remaining strictly distinct from the analytical risk model's **Attack Success Rate (ASR)**.

---

## 2. 64-Byte Testbed Telecommand Frame Layout

| Byte Offset | Field | Size | Description |
| :--- | :--- | :---: | :--- |
| `0..11` | CCSDS TC Frame | 12 B | Primary header (6 B, expected `ccsds_len = 5`) + payload (6 B) |
| `12` | `role` | 1 B | Subject privilege attribute (`0x01` = FlightOps, `0x02` = LowPriv) |
| `13` | `src_id` | 1 B | Sender identifier (`0x01..0xFF`) |
| `14` | `pkt_class` | 1 B | Logging tag only (**never** used in PEP security decisions) |
| `15` | `los_state` | 1 B | Trusted test-harness abstraction of contact state (`0` = AOS, `1` = LOS; not a sender-controlled attribute in flight deployment) |
| `16..23` | `seq_num` | 8 B | Big-endian monotonic `uint64` anti-replay counter per `src_id` |
| `24..27` | `expiry` | 4 B | Big-endian `uint32` Unix token expiration timestamp |
| `28..31` | `run_id` | 4 B | Batch or cycle index for logging |
| `32..63` | `hmac` | 32 B | HMAC-SHA-256 tag computed over bytes `0..31` |

---

## 3. Summary of Experimental Results

### 3.1 Section VII-B: Progressive Four-Mode Coverage & Host Processing Overhead (10 Consecutive Measurement Batches)
- **Workload:** 50-packet warm-up excluded; 10 consecutive measurement batches (1,000 packets/batch; 10,000 measured packets/mode at 20 pkt/s) within a single continuous cFS execution without resetting stateful PEP tables between batches: 2,000 `BENIGN` + 8,000 SPARTA-derived malicious telecommands (2,000 each: ATK-1 `EX-0013.02`, ATK-2 `EX-0001.01`/`IA-0008.01`, ATK-3 `IA-0007.02`, ATK-4 `EX-0013.01`).
- **Observed Benign Drops (FPR):** **0/2,000** across all four modes.

| PEP Mode | Active Onboard Controls | Mitigated Classes | Benign Med. (µs) | ΔMed. (µs) | Benign P95 (µs) | Early-Drop Med. (µs) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Mode 0:** Baseline | None onboard (Perimeter bypass) | 0/4 | 2.659 | — | 13.833 | — |
| **Mode 1:** Input Val. | TE-20, TE-22 (CCSDS format check) | 1/4 (ATK-1) | 2.814 | +0.155 | 15.533 | 0.110 |
| **Mode 2:** Auth + ABAC | + TE-09, TE-04 (HMAC-SHA-256, Replay, ABAC) | 3/4 (ATK-1–3) | 6.447 | +3.788 | 16.980 | 3.311 |
| **Mode 3:** Auto-Isol. | + TE-15a (Generalized LOS rate quarantine, $T=5$) | **4/4 (ATK-1–4†)** | **8.828** | **+6.168** | **21.230** | **3.677** |

*Robust percentiles (Median and P95) are reported over the identical 2,000 `BENIGN` commands per mode because occasional OS scheduling preemptions on the non-real-time Linux host introduce heavy-tailed outliers (full per-packet logs are archived in the CSV datasets). †Per-attack packet pass counts (`Passed/Sent`) across Modes 0–3:*

| Attack Class (SPARTA Ref.) | M0 | M1 | M2 | M3 | Validated Control Subset |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **ATK-1** (`EX-0013.02`, Malformed CCSDS) | 2,000/2,000 | 0/2,000 | 0/2,000 | 0/2,000 | TE-20, TE-22 (frame subset) |
| **ATK-2** (`EX-0001.01`/`IA-0008.01`, Replay) | 2,000/2,000 | 2,000/2,000 | 0/2,000 | 0/2,000 | TE-09 (HMAC + 64-b window) |
| **ATK-3** (`IA-0007.02`, Low-Priv `0x1880`) | 2,000/2,000 | 2,000/2,000 | 0/2,000 | 0/2,000 | TE-04 (role-to-`MsgID` ABAC) |
| **ATK-4** (`EX-0013.01`, LOS Valid Flood) | 2,000/2,000 | 2,000/2,000 | 2,000/2,000 | 22/2,000 (1.1%) | TE-15a (reversible quarantine) |
| **Total Malicious (8,000 / Mode)** | **8,000/8,000** | **6,000/8,000** | **2,000/8,000** | **22/8,000** | **Component Verification** |

*Modes 1–2 enforce deterministic format, cryptographic, anti-replay, and ABAC rules (complete rejection of targeted classes), whereas Mode 3 enforces a stateful rate window ($T=5$ pkt/s) that permits 22 initial `ATK-4` packets in Batch 1 before triggering persistent quarantine (0/1,800 passed across Batches 2–10).*

---

### 3.2 Section VII-B: Static ELF Code & Memory Footprint (`ci_lab.so`, GNU `size`/`nm`)

| Mode | `.text` (B) | `.data` (B) | `.bss` (B) | Total (B) | Δ`.text` (B) | ΔTotal |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode 0 (Baseline)** | 12,984 | 936 | 160 | 14,080 | — | — |
| **Mode 1 (Input Val.)** | 13,102 | 936 | 160 | 14,198 | +118 | +118 B (+0.12 KiB) |
| **Mode 2 (Auth + ABAC)** | 17,962 | 960 | 6,416 | 25,338 | +4,978 | +11,258 B (+10.99 KiB) |
| **Mode 3 (Auto-Isol.)** | 18,423 | 960 | 10,512 | 29,895 | +5,439 | +15,815 B (+15.44 KiB) |

*Values report static ELF section sizes (distinct from runtime stack/heap). Static tables account for 10,240 B in Mode 3 (`zta_replay_tbl`: 6,144 B / 6.00 KiB; `zta_rate_tbl`: 4,096 B / 4.00 KiB), measured on the baseline four-mode PEP build (`v2.0`) prior to adding the `v2.1` runtime policy/threshold flags (`ZTA_LOS_POLICY`, `ZTA_LOS_MAX_PKTS`).*

---

### 3.3 Section VII-C: Comparative LOS Policy Enforcement (10 Consecutive AOS–LOS–AOS Cycles)
- **Workload:** 50-packet warm-up excluded; 10 consecutive AOS–LOS–AOS cycles within a continuous cFS execution with per-cycle authenticated FlightOps AOS quarantine resets (5,000 measured packets/policy at 20 pkt/s: 200 AOS benign, 200 AOS unauth [0/200 passed across all policies], 500 LOS valid benign at 2.5 pkt/s, 500 LOS expired benign, 1,000 LOS unauth [500 replay + 500 ABAC], 2,000 LOS flood, and 600 AOS recovery commands).
- **Baselines:** Fail-Closed (`ZTA_LOS_POLICY=0`) and Fail-Open (`ZTA_LOS_POLICY=1`) represent intentionally simplified boundary policies for controlled comparison against the proposed hybrid ZTA policy (`ZTA_LOS_POLICY=2`).

| LOS Policy (`ZTA_LOS_POLICY`) | AOS Benign Forwarded | LOS Valid Forwarded | LOS Expired Rejected | LOS Unauth Passed | LOS Flood Passed | AOS Recovery | LOS Valid Med. (µs) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Fail-Closed (`0`)** | 200/200 | **0/500** | 500/500 | 0/1,000 | 0/2,000 | 600/600 | 0.031 *(drop)* |
| **Fail-Open (`1`)** | 200/200 | 500/500 | **0/500** | **1,000/1,000** | **2,000/2,000** | 600/600 | 1.923 |
| **Hybrid ZTA (`2`, $T=5$)** | **200/200** | **500/500** | **500/500** | **0/1,000** | **50/2,000 (2.5%)** | **600/600** | **14.242** |

---

### 3.4 Section VII-D: Benign Burst Tolerance & Post-Quarantine AOS Recovery (5 Consecutive AOS-Reset Cycles per $T$)

| Threshold $T$ (pkt/s) | $B=3$ Passed | $B=5$ Passed | $B=8$ Passed | $B=12$ Passed | ATK-4 Flood Passed (Rate) | AOS Recovery |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **5** | 15/15 | 25/25 | 25/40 (62.5%) | 25/60 (41.7%) | 25/1,000 (2.5%) | 5/5 cyc. |
| **10** | 15/15 | 25/25 | 40/40 | 50/60 (83.3%) | 50/1,000 (5.0%) | 5/5 cyc. |
| **20** | 15/15 | 25/25 | 40/40 | 60/60 | 100/1,000 (10.0%) | 5/5 cyc. |

*Exact packet counts aggregated over 5 cycles per threshold (total burst commands: 15, 25, 40, and 60 for $B=3, 5, 8, 12$; total ATK-4 flood packets: 1,000). AOS recovery denotes full command-forwarding restoration after authenticated FlightOps resynchronization in all 5 cycles.*

---

## 4. Repository Structure

```text
zta-cfs-validation/
├── src/
│   └── zta_pep.h                         # Self-contained onboard PEP (HMAC-SHA-256, Replay, ABAC, TE-15a, LOS policies)
├── patches/
│   └── ci_lab_zta.patch                  # NASA cFS v7.0.1 CI_LAB integration patch
├── scripts_los/
│   ├── zta_bench_los_policy.py           # Sec. VII-C: AOS-LOS-AOS 3-policy traffic generator
│   ├── zta_bench_burst_recovery.py       # Sec. VII-D: Benign burst & AOS quarantine recovery generator
│   └── analyze_los_burst.py              # Aggregator for Sec. VII-C & VII-D CSV datasets
├── data_los/
│   ├── los_policy0_failclosed.csv        # Raw 10-cycle CSV (Fail-Closed)
│   ├── los_policy1_failopen.csv          # Raw 10-cycle CSV (Fail-Open)
│   ├── los_policy2_hybrid.csv            # Raw 10-cycle CSV (Proposed Hybrid ZTA)
│   ├── burst_T5.csv                      # Raw 5-cycle burst/recovery CSV (T=5)
│   ├── burst_T10.csv                     # Raw 5-cycle burst/recovery CSV (T=10)
│   └── burst_T20.csv                     # Raw 5-cycle burst/recovery CSV (T=20)
└── README.md
```
*(Original four-mode `v2.0` benchmark scripts and 10-batch CSV datasets remain archived alongside the `v2.1` additions.)*

---

## 5. Reproduction Instructions

### 5.1 Build & Static ELF Footprint Measurement
```bash
# Copy header & apply patch inside NASA cFS v7.0.1 root ($CFS_ROOT)
cp src/zta_pep.h "$CFS_ROOT/apps/ci_lab/fsw/src/zta_pep.h"
cd "$CFS_ROOT/apps/ci_lab" && git apply ~/zta-cfs-validation/patches/ci_lab_zta.patch

# Measure Mode 0..3 static ELF footprint
# (Note: Table 3.2 reports the baseline v2.0 four-mode build; v2.1 adds small runtime policy/threshold helpers.)
cd "$CFS_ROOT"
for MODE in 0 1 2 3; do
  sed -i "s/#define ZTA_PHASE_MODE .*/#define ZTA_PHASE_MODE $MODE/" apps/ci_lab/fsw/src/ci_lab_app.c
  make -j$(nproc) && make install
  size build/exe/cpu1/cf/ci_lab.so
  nm --size-sort -S build/exe/cpu1/cf/ci_lab.so | grep zta
done
```

### 5.2 Run Section VII-C (LOS Policy Comparison) & Section VII-D (Burst/Recovery)
With `ZTA_PHASE_MODE` built as `3`, launch cFS (`./core-cpu1` in `$CFS_ROOT/build/exe/cpu1`) with the desired policy/threshold environment variables:

```bash
# Terminal 1 (cFS) — example for Hybrid ZTA (Policy 2, T=5)
export ZTA_HMAC_KEY="TAES_ZTA_TEST_KEY_2026"
export ZTA_LOS_POLICY=2          # 0=Fail-Closed, 1=Fail-Open, 2=Hybrid ZTA
export ZTA_LOS_MAX_PKTS=5        # 5, 10, or 20 for Sec. VII-D burst tests
export ZTA_CSV_FILE="$HOME/zta-cfs-validation/data_los/los_policy2_hybrid.csv"
./core-cpu1

# Terminal 2 (Traffic Generator)
export ZTA_HMAC_KEY="TAES_ZTA_TEST_KEY_2026"
python3 ~/zta-cfs-validation/scripts_los/zta_bench_los_policy.py --runs 10 --rate 20
# or for Sec. VII-D burst/recovery:
python3 ~/zta-cfs-validation/scripts_los/zta_bench_burst_recovery.py --runs 5

# Aggregate all Sec. VII-C & VII-D metrics
python3 ~/zta-cfs-validation/scripts_los/analyze_los_burst.py
```

---

## 6. Release History
- **`v2.1` (Current):** Added Section VII-C (3-policy LOS comparison), Section VII-D (benign burst tolerance & authenticated AOS recovery), Mode 0–3 static ELF footprint documentation, and updated `zta_pep.h` with runtime `ZTA_LOS_POLICY` / `ZTA_LOS_MAX_PKTS` configuration.
- **`v2.0`:** 10-batch progressive four-mode benchmark with self-contained HMAC-SHA-256, 64-bit sliding-window anti-replay, ABAC, and generalized LOS rate quarantine.
