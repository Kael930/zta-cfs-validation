# Phased ZTA Migration Framework: NASA cFS Empirical Validation Artifacts (v2)

This repository contains the complete reproducibility artifacts—onboard Policy Enforcement Point (PEP) source code, NASA Core Flight System (cFS) `CI_LAB` integration patch, SPARTA-mapped traffic generator, statistical analysis script, and raw per-packet measurement logs—supporting our IEEE TAES manuscript:

> **"A Phased Zero Trust Migration Framework for Heterogeneous Space Systems: Requirements Traceability and Model-Based Evaluation"**

---

## 1. Repository Structure & File Manifest

| Path | Role | Detailed Description |
| :--- | :--- | :--- |
| `src/zta_pep.h` | Onboard PEP Header | Self-contained C header implementing 4 migration modes (`ZTA_PHASE_MODE` 0–3): CCSDS length/format validation (`TE-20/22`), FIPS 180-4 / RFC 2104 **HMAC-SHA-256** authentication with constant-time comparison, per-sender 64-bit sliding-window anti-replay (`TE-09`), ABAC (`TE-04`), and generalized LOS time-window rate isolation (`TE-15`). Zero external crypto library dependency. |
| `patches/ci_lab_zta.patch` | cFS Integration Patch | Exact `git diff` against NASA cFS v7.0.1 `apps/ci_lab/fsw/src/ci_lab_app.c` showing `CLOCK_MONOTONIC` latency instrumentation, `ZTA_EvaluatePacket()` gating prior to `CFE_SB_TransmitBuffer()`, and CSV logging via `ZTA_LogResult()`. |
| `scripts/zta_bench_4mode.py` | Traffic Generator | Python UDP telecommand generator (`127.0.0.1:1234`) producing 5 packet classes (`BENIGN`, `ATK1_MALFORM`, `ATK2_REPLAY`, `ATK3_ABAC`, `ATK4_LOS_FLOOD`) with configurable warm-up (`--warmup`), transmission rate (`--rate`), and repeated runs (`--runs`). |
| `scripts/analyze_4mode.py` | Verification Script | Statistical evaluator excluding warm-up packets and reporting `BENIGN` availability (`FPR`), overall and per-attack **Attack Pass Rate (`APR`)**, `BENIGN`-only latency (`Mean`, `Std`, `Median`, `P95`, `P99`), and early-drop latency. |
| `data/cfs_mode0_v2.csv` – `data/cfs_mode3_v2.csv` | Raw Empirical Logs | Per-packet logs for Modes 0–3 (`10,050` data rows per mode: `50` warm-up + `10` runs × `1,000` measured packets). |

---

## 2. Quick Verification (Reproduce Paper Tables Directly)

No cFS build is required to verify the reported metrics from the raw logs:

```bash
python3 scripts/analyze_4mode.py --data-dir data
```

### Summary of Empirical Results (10 Runs, 2,000 BENIGN + 8,000 Attack Packets per Mode)

| Mode | Active Onboard Controls | BENIGN Avail. (FPR) | Overall APR | BENIGN Median (µs) | Median Overhead | BENIGN P95 (µs) | BENIGN Mean ± Std (µs) | BENIGN P99 (µs) | Early-Drop Median (µs) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode 0** | Baseline (No Onboard PEP) | 100.00% (0.00%) | 100.00% (8,000/8,000) | 2.659 | — | 13.833 | 8.099 ± 51.951 | 57.463 | — |
| **Mode 1** | Input Validation (`TE-20/22`) | 100.00% (0.00%) | 75.00% (6,000/8,000) | 2.814 | +0.155 µs | 15.533 | 7.892 ± 41.175 | 37.081 | 0.110 |
| **Mode 2** | + HMAC-SHA-256, Anti-Replay, ABAC (`TE-09/04`) | 100.00% (0.00%) | 25.00% (2,000/8,000) | 6.447 | +3.788 µs | 16.980 | 8.711 ± 18.842 | 28.593 | 3.311 |
| **Mode 3** | + Generalized LOS Auto-Isolation (`TE-15`) | 100.00% (0.00%) | **0.27%** (22/8,000) | **8.828** | **+6.168 µs** | **21.230** | **12.470 ± 24.736** | 130.652 | 3.677 |

*Notes:*
- `APR` (Attack Pass Rate) is reported separately from the architectural model's `ASR` to distinguish controlled cFS packet-filtering measurements from analytical risk estimates.
- `BENIGN` latency is measured strictly over the identical 2,000 legitimate flight commands across all modes for an apples-to-apples comparison. Upper-tail P99 spikes reflect non-real-time Linux/WSL OS scheduling jitter rather than deterministic PEP computation cost.

---

## 3. Packet Layout & CSV Schema

### 64-Byte Experimental Telecommand Frame
| Byte Offset | Field | Description |
| :--- | :--- | :--- |
| `0..11` | `CCSDS TC` | CCSDS Telecommand Primary Header (6 B) + Payload (6 B) |
| `12` | `role` | Sender privilege role (`0x01`: FlightOps, `0x02`: LowPriv) |
| `13` | `src_id` | Sender identifier (`0x01`–`0xFF`) |
| `14` | `pkt_class` | Experiment logging tag only (`0`: WARMUP, `1`: BENIGN, `2`–`5`: ATK1–ATK4; never referenced by PEP security logic) |
| `15` | `los_state` | Link status flag (`0`: AOS, `1`: LOS) |
| `16..23` | `seq_num` | 64-bit big-endian monotonic anti-replay counter per `src_id` |
| `24..27` | `expiry` | 32-bit big-endian Unix expiration timestamp |
| `28..31` | `run_id` | 32-bit big-endian repetition index (`1..10`) |
| `32..63` | `hmac` | 32-byte HMAC-SHA-256 digest computed over bytes `0..31` using `ZTA_HMAC_KEY` |

### CSV Log Schema (`data/cfs_mode*_v2.csv`)
`run_id,mode,pkt_class,src_id,seq_num,los_state,status,reason,latency_us`

---

## 4. Full End-to-End Reproduction on NASA cFS v7.0.1

1. **Install Header & Apply `CI_LAB` Patch:**
```bash
cp src/zta_pep.h <CFS_ROOT>/apps/ci_lab/fsw/src/zta_pep.h
cd <CFS_ROOT>/apps/ci_lab
git apply /path/to/zta-cfs-validation/patches/ci_lab_zta.patch
```

2. **Select Mode (`0`, `1`, `2`, or `3`) and Build cFS:**
   Set `#define ZTA_PHASE_MODE <0|1|2|3>` in `apps/ci_lab/fsw/src/ci_lab_app.c`, export runtime environment variables, and build:
```bash
export ZTA_HMAC_KEY="your_strong_testbed_secret_key_2026"
export ZTA_LOG_DIR="/path/to/output_dir"
cd <CFS_ROOT> && make && make install
cd <CFS_ROOT>/build/exe/cpu1 && ./core-cpu1
```

3. **Run Benchmark (in a second terminal with the same `ZTA_HMAC_KEY`):**
```bash
export ZTA_HMAC_KEY="your_strong_testbed_secret_key_2026"
python3 scripts/zta_bench_4mode.py --runs 10 --rate 20 --warmup 50
```

4. **Analyze Collected Logs:**
```bash
python3 scripts/analyze_4mode.py --data-dir /path/to/output_dir
```
