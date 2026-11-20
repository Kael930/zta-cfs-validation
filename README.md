# Phased ZTA Migration Framework: NASA cFS Empirical Validation Artifacts

This repository provides the source code, SPARTA-mapped traffic generator, and raw empirical logs supporting the NASA Core Flight System (cFS) validation in our IEEE TAES manuscript:
"A Phased Zero Trust Migration Framework for Resilient Space Systems: Lifecycle-Aware Design and Evaluation Methodology."

## Repository Structure
- src/zta_pep.h: Lightweight onboard Policy Enforcement Point (PEP) integrated into cFS CI_LAB supporting 4 migration modes (ZTA_PHASE_MODE 0--3).
- scripts/zta_bench_4mode.py: 5-class CCSDS telecommand generator (200 legitimate + 800 SPARTA-mapped attack packets).
- scripts/analyze_4mode.py: Statistical analysis script computing ASR, Mean, Median, and P99 latency.
- data/cfs_mode0.csv -- cfs_mode3.csv: Raw per-packet measurement logs (n = 1,000 per mode) collected via CLOCK_MONOTONIC.

## Quick Verification
Run: python3 scripts/analyze_4mode.py

## Summary of Empirical Results
| Mode | Active Controls | Allowed | Blocked | ASR (%) | Mean (us) | Median (us) | P99 (us) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Mode 0 (Legacy / Ph1) | None onboard (Perimeter-only) | 1,000 | 0 | 100.00 | 3.998 | 2.094 | 25.569 |
| Mode 1 (Ph2-A) | TE-20, TE-22 (Input Validation) | 800 | 200 | 75.00 | 5.552 | 2.550 | 58.986 |
| Mode 2 (Ph2-B) | + TE-09, TE-04 (Auth + ABAC) | 400 | 600 | 25.00 | 3.017 | 1.515 | 15.408 |
| Mode 3 (Ph3) | + TE-15 (LOS Auto-Isolation) | 205 | 795 | 0.62 | 5.477 | 3.629 | 16.731 |
