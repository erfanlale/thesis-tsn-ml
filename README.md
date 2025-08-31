# MinimalPSFP-Attack-ML

End-to-end OMNeT++/INET TSN scenario with IEEE 802.1Qci **Per-Stream Filtering & Policing (PSFP)**, 802.1Qbv **Time-Aware Shaping (TAS)**, and a **real-time ML** inference loop.

## Repo layout

* `simulations/omnetpp.ini` – scenarios & parameters (500 ms run, 1 ms windows, gPTP overrides)
* `src/` – C++: `DataCollector`, `TSNMLInferenceEngine`, helpers
* `scripts/` – Python: training (`train_tsn_extended_model.py`), Keras→Frugally-Deep converter
* `ml_models/` – exported models + normalization (`*_norm.json`)
* `results_flat/` – per–run CSV outputs

## Scenarios

* **Baseline** – nominal traffic
* **DoSAttack** – external flood (100–400 ms)
* **TimingAttack** – clock drift + PCP6 gate starvation + microbursts (50–450 ms)
* **SpoofingAttack** – impostor frames mimicking critical stream

## Quickstart

### Build

```bash
make MODE=release -j4
# exe: out/clang-release/MinimalPSFP-Attack-ML
```

### Run

```bash
./out/clang-release/MinimalPSFP-Attack-ML -u Cmdenv -c Baseline -r 0
# other configs: DoSAttack | TimingAttack | SpoofingAttack
```

### Configuration highlights (already set in INI)

* **Sim windowing:** 500 ms total, **1 ms** feature windows & inference cadence
* **gPTP aligned to short runs:**

```ini
**.gptp.syncInterval = 10ms
**.gptp.syncInitialOffset = 1ms
**.gptp.pdelayInterval = 50ms
**.gptp.pdelayInitialOffset = 1ms
```

* **Collector:** egress vantage on central switch; `includeControlFramesInThroughput=true`

## Outputs

### Per-packet (egress + filter events)

`results_flat/tsn_signals_${config}-#${rep}.csv`
Useful for audits (PCP, VLAN, gating, metering). Packet counts are **vantage-based** (a logical packet may appear multiple times).

### Window features (1 ms)

`results_flat/window_features_${config}-#${rep}.csv`
Columns (superset; some may be sparse):

**Base 7**

* `throughput_bps_tx`, `throughput_bps_rx`
* `packets_sent`, `packets_received`, `packets_dropped`
* `drop_rate`, `queue_length_max`

**Timing / servo (sparse by design)**

* `ptp_offset_mean`, `ptp_offset_max`, `rate_ratio_mean`, `peer_delay_mean`
* `e2e_delay_avg`, `e2e_delay_max`, `e2e_delay_std`

**Availability & counters**

* `ptp_samples`, `e2e_samples` (per window)
* (training may also derive `has_ptp`, `has_e2e` masks)

**Missing-value convention**

* Newer runs: **`-1`** means “no samples in window”; counters report `0`
* Legacy runs: zeros were written when no samples; the trainer handles this by mapping legacy-zeros→NaN using the sample counters when present

## Train (extended feature set)

```bash
# conda env contains tensorflow + frugally-deep converter deps
conda run -n tf-omnet python scripts/train_tsn_extended_model.py
```

Artifacts in `ml_models/`:

* `tsn_extended.keras`
* `tsn_extended_norm.json`  ← contains `feature_order`, `mean`, `std`, and optional `recommended_threshold`
* `tsn_extended_fdeep.json` (for C++ inference)

> The trainer handles sparse timing features (`-1`→NaN, legacy zeros) and may drop constant `throughput_bps_rx` if structurally zero at the chosen vantage.

## In-simulation inference (1 ms)

In `simulations/omnetpp.ini`:

```ini
*.mlInferenceEngine.modelPath = "../ml_models/tsn_extended_fdeep.json"
*.mlInferenceEngine.normPath  = "../ml_models/tsn_extended_norm.json"
*.mlInferenceEngine.inferenceInterval = 1ms
```

* The engine reads `feature_order` and z-scores using the saved `mean/std`.
* If your engine build is still **F7-only**, point it to the 7-feature model/JSON instead; otherwise it will refuse non-matching widths (by design) to prevent silent mis-inference.

## Sanity checklist (post-run)

* `window_features_*`: 500 rows per run (0–499 ms)
* Baseline: `drop_rate≈0`, `queue_length_max` low; \~**50** windows with non-missing `ptp_offset_*`
* TimingAttack: elevated `drop_rate` & queueing; sparse `ptp_*` as above; labels match scenario timing
* If `peer_delay_mean` is missing in most windows, that’s expected at 50 ms cadence with TAS starvation—document as sparse

## Troubleshooting

* **Zeros vs missing:** `-1` (new) or zero-with-zero-samples (legacy) both mean “no observation this window.” Treat as missing in training/inference.
* **RX throughput is 0:** expected at egress vantage; the trainer may drop it automatically.
* **Per-packet VLAN/PCP look odd in DoS:** those frames may bypass host encoders; rely on switch-side classification + metering for ground truth.

## License

Project code for academic use; INET and related frameworks retain their own licenses.

---
