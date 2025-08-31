# MinimalPSFP-Attack-ML

End-to-end OMNeT++/INET TSN scenario with Per-Stream Filtering and Policing (PSFP), Time-Aware Shaping (Qbv), and a real-time ML inference engine for anomaly detection.

## Repository layout
- `simulations/omnetpp.ini` — Scenario configs and component parameters
- `src/` — C++ sources: `DataCollector`, `TSNMLInferenceEngine`, helpers
- `scripts/` — Python: training (`train_tsn_extended_model.py`), converter
- `ml_models/` — Trained model artifacts + reports
- `results_flat/` — Simulation outputs (CSV)

## What’s included
- Minimal TSN network with scenarios: Baseline, DoSAttack, TimingAttack, SpoofingAttack
- Windowed feature CSVs with timing/servo observables and sample counters
- Extended 15-feature ML model exported to Frugally-Deep JSON
- In-sim inference at 1 ms cadence using the exported model

## Build
```
make MODE=release -j4
```
Executable: `out/clang-release/MinimalPSFP-Attack-ML`

## Run
```
./out/clang-release/MinimalPSFP-Attack-ML -u Cmdenv -c Baseline -r 0
```
Other configs: `DoSAttack`, `TimingAttack`, `SpoofingAttack`

## Data outputs
- Per-packet: `results_flat/tsn_signals_${configname}-#${repetition}.csv`
- Window features: `results_flat/window_features_${configname}-#${repetition}.csv`

## Train (extended 15 features)
```
conda run -n tf-omnet python scripts/train_tsn_extended_model.py
```
Artifacts in `ml_models/`:
- `tsn_extended.keras`, `tsn_extended_fdeep.json`, `tsn_extended_norm.json`
- `training_artifacts/` (inputs_used, label_counts, metrics, history, TRAINING_REPORT.md)

## Inference configuration
In `simulations/omnetpp.ini`:
```
*.mlInferenceEngine.modelPath = "../ml_models/tsn_extended_fdeep.json"
*.mlInferenceEngine.normPath  = "../ml_models/tsn_extended_norm.json"
*.mlInferenceEngine.inferenceInterval = 1ms
```
The engine reads the saved `feature_order`, normalization stats, and `recommended_threshold`.

## Notes
- Missing timing/servo metrics use `-1.0` (newer CSVs) and are masked in training/inference.
- `throughput_bps_rx` can be structural zero at the chosen vantage and may be dropped automatically.

## License
This project builds upon INET and CoRE4INET; see their licenses. Project-specific code is provided for academic research.
