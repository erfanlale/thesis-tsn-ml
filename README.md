# MinimalPSFP-Attack-ML

End-to-end OMNeT++/INET TSN scenario with IEEE 802.1Qci **Per-Stream Filtering & Policing (PSFP)**, 802.1Qbv **Time-Aware Shaping (TAS)**, and a **real-time ML** inference loop.

## Repo layout

* `simulations/omnetpp.ini` – TSN attack scenarios & IEEE 802.1Qci PSFP configuration (500ms runs, 1ms windows, gPTP timing)
* `simulations/MinimalAttackNetwork.ned` – 7-node network topology with TSN switch, legitimate devices, and attack nodes
* `src/` – C++ modules: `DataCollector` (time-windowed signal aggregation), `TSNMLInferenceEngine` (real-time Frugally-Deep inference), `CsvWriter` (CSV output utilities)
* `scripts/` – Python ML pipeline: `train_tsn_extended_model.py` (15-feature neural network training), `convert_to_frugally_deep.py` (Keras→C++ model conversion), `audit_trainer.py` (training validation)
* `ml_models/` – exported models: `tsn_extended_fdeep.json` (C++ inference model), `tsn_extended_norm.json` (z-score normalization), training artifacts
* `simulations/results_flat/` – per-run outputs: `window_features_*.csv` (1ms ML features), `tsn_signals_*.csv` (per-packet events), `*.sca/.vec` (OMNeT++ statistics)

## Scenarios

* **Baseline** – nominal TSN operation with critical sensor (1ms intervals), sensor monitoring (50ms), status updates (10ms), display data (50ms)
* **DoSAttack** – external flood attack targeting critical sensor port (200kHz rate, 1500B packets, 100–400ms duration)
* **TimingAttack** – clock drift attack (500ppm) + PCP6 gate starvation (490us closed, 10us open) + microbursts (10–100us intervals, 50–450ms)
* **SpoofingAttack** – compromised node impersonating critical sensor with PCP7/VLAN10 encoding (10x faster rate, 150–350ms duration)

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

## Network Topology

**MinimalAttackNetwork** (7 nodes total):

- **masterClock**: TSN grandmaster with gPTP master ports
- **centralSwitch**: TSN switch with full IEEE 802.1Qci PSFP implementation
- **mainECU**: Main electronic control unit (1Gbps uplink)
- **criticalSensor**: Safety-critical sensor (100Mbps, 1kHz transmission)
- **display**: Display unit (100Mbps, 20Hz updates)
- **attackerExternal**: External attack node (100Mbps)
- **compromisedNode**: Internal compromised node (100Mbps)

**Link configuration**: Mixed 100Mbps/1Gbps Ethernet links with explicit bitrate settings to match TSN requirements.

## IEEE 802.1Qci PSFP Implementation

**Complete PSFP stack** implemented on central switch:

### Stream Classification
- **8 stream types** with unique PCP/VLAN mappings:
  - `critical_control` (PCP7, VLAN10) - highest priority safety traffic
  - `status_updates` (PCP5, VLAN30) - ECU status messages
  - `display_data` (PCP3, VLAN20) - display updates
  - `sensor_monitoring` (PCP4, VLAN25) - diagnostic data
  - `external_attack` (PCP0, VLAN40) - attack traffic classification
  - `compromised_attack` (PCP0, VLAN41) - internal attack classification
  - `gptp` (PCP6, VLAN0) - time synchronization (priority-tagged)
  - `default_stream` (PCP0, VLAN0) - fallback classification

### Stream Filtering & Policing
- **DualRateThreeColorMeter** implementation per stream
- **Committed Information Rates (CIR)**:
  - Critical control: 10Mbps CIR, 5Mbps EIR
  - Status updates: 5Mbps CIR, 2Mbps EIR
  - Display data: 2Mbps CIR, 1Mbps EIR
  - Attack streams: 50kbps CIR (detection threshold)
  - gPTP: 1Mbps CIR (timing protection)

### Time-Aware Shaping (TAS)
- **8 priority classes** with time-gated transmission:
  - PCP7: 250us open, 250us closed (critical traffic)
  - PCP6: 200us open, 300us closed (gPTP timing)
  - PCP5: 150us open, 350us closed (status updates)
  - PCP4: 100us open, 400us closed (monitoring)
  - PCP3: 100us open, 400us closed (display)
  - PCP2: 50us open, 450us closed (best effort)
  - PCP1: 50us open, 450us closed (best effort)
  - PCP0: 25us open, 475us closed (attack traffic)

## DataCollector Module

**Time-windowed signal aggregation** for ML feature extraction:

### Signal Subscription
Subscribes to TSN signals across all modules:
- **Packet events**: `packetSent`, `packetReceived`, `packetDropped`
- **Queue metrics**: `queueLength`, `queueingTime`, `queueBitLength`
- **TSN timing**: `ptp.offsetNanoseconds`, `ptp.rateRatio`, `ptp.peerDelay`
- **End-to-end delay**: `app.endToEndDelay`
- **PSFP meters**: `meter.committedConformingPackets`, `meter.packetFiltered`
- **Gate states**: `transmissionGate.gateStateChanged`

### Feature Aggregation
**1ms time windows** with 15 ML features:
- **Throughput metrics**: `throughput_bps_tx`, `throughput_bps_rx`
- **Packet counters**: `packets_sent`, `packets_received`, `packets_dropped`, `drop_rate`
- **Queue metrics**: `queue_length_max`
- **gPTP timing**: `ptp_offset_mean`, `ptp_offset_max`, `rate_ratio_mean`, `peer_delay_mean`
- **E2E timing**: `e2e_delay_avg`, `e2e_delay_max`, `e2e_delay_std`
- **Sample counters**: `ptp_samples`, `e2e_samples` (for sparsity handling)

### Output Formats
- **CSV per window**: `window_features_*.csv` (ML-ready features)
- **Per-packet CSV**: `tsn_signals_*.csv` (detailed packet events)
- **OMNeT++ vectors**: `*.vec` files (signal recordings)

## ML Pipeline

**15-feature neural network** trained on simulation data:

### Training Process
- **Data sources**: `window_features_*.csv` from multiple simulation runs
- **Feature set**: 15 features with z-score normalization
- **Architecture**: Dense neural network with dropout regularization
- **Labels**: Binary classification (normal vs anomaly)
- **Validation**: Stratified k-fold cross-validation

### Model Export
- **Keras model**: `tsn_extended.keras` (Python training artifact)
- **C++ model**: `tsn_extended_fdeep.json` (Frugally-Deep format)
- **Normalization**: `tsn_extended_norm.json` (mean/std statistics)

### Frugally-Deep Integration
- **Header-only C++ library** for neural network inference
- **Zero dependencies** beyond standard library
- **Sub-millisecond inference** suitable for 1ms TSN windows
- **Tensor operations** optimized for embedded/real-time use

## TSNMLInferenceEngine Module

**Real-time ML inference** integrated into simulation:

### Model Loading
- **Runtime loading** of Frugally-Deep JSON models
- **Normalization application** using saved statistics
- **Input validation** with feature dimension checking

### Inference Process
- **1ms intervals** synchronized with data collection windows
- **Feature preprocessing** with missing value handling (-1 → NaN → 0)
- **Z-score normalization** using training statistics
- **Binary classification** output (normal/anomaly probabilities)

### Integration Points
- **Data source**: Pulls features from DataCollector module
- **Output logging**: `inference_*.csv` with timestamps and probabilities
- **Signal emission**: `inferenceResult` signal for OMNeT++ recording
- **Display updates**: Module display string shows current classification

### Performance Tracking
- **Inference latency** measurement and emission
- **Total inference count** and timing statistics
- **Attack detection** state management

## Outputs

### Simulation Results (`simulations/results_flat/`)

#### Per-packet Events
`tsn_signals_${config}-#${rep}.csv` - Detailed packet-level events from egress vantage:
- **Stream identification**: stream name, source/destination MAC, PCP, VLAN
- **Timing information**: packet timestamp, queue length, gate state
- **PSFP actions**: meter conformance (green/yellow/red), filtering decisions
- **Network metrics**: packet size, end-to-end delay, queueing time

#### Window Features (1ms)
`window_features_${config}-#${rep}.csv` - ML-ready aggregated features:
- **Throughput metrics**: `throughput_bps_tx`, `throughput_bps_rx` (bits/sec)
- **Packet statistics**: `packets_sent`, `packets_received`, `packets_dropped`, `drop_rate`
- **Queue metrics**: `queue_length_max` (maximum queue depth)
- **gPTP timing**: `ptp_offset_mean`, `ptp_offset_max`, `rate_ratio_mean`, `peer_delay_mean`
- **E2E timing**: `e2e_delay_avg`, `e2e_delay_max`, `e2e_delay_std` (application-level delays)
- **Sample counters**: `ptp_samples`, `e2e_samples` (data availability indicators)

#### Inference Results
`inference_${config}-#${rep}.csv` - Real-time ML inference outputs:
- **Timestamps**: simulation time, window start/end times
- **Probabilities**: `p_normal`, `p_anomaly` (model outputs)
- **Classification**: `pred_label` (NORMAL/ANOMALY)
- **Ground truth**: `gt_label` (scenario-based labels)
- **Feature values**: All 15 input features for transparency

#### OMNeT++ Statistics
`*.sca` (scalars) & `*.vec` (vectors) - Standard OMNeT++ result files:
- **Signal recordings**: All subscribed signals with timestamps
- **Module statistics**: Performance metrics and counters
- **Event logs**: Detailed simulation events (when enabled)

### Missing Value Handling

**Standardized conventions** for sparse timing data:
- **`-1` values**: Indicate no samples available in window (newer runs)
- **Zero values**: Legacy format when no samples present
- **Training compatibility**: Models handle both formats by using sample counters

## ML Training Pipeline

**15-feature neural network** trained on simulation-generated data:

```bash
# Requires conda environment with TensorFlow + ML dependencies
conda run -n tf-omnet python scripts/train_tsn_extended_model.py
```

### Training Process
- **Data collection**: Aggregates `window_features_*.csv` from multiple runs (160 files total)
- **Feature engineering**: 15 features with z-score normalization per training set
- **Architecture**: Dense neural network with dropout regularization and early stopping
- **Validation**: Stratified 5-fold cross-validation with balanced sampling
- **Output metrics**: Classification report, confusion matrix, ROC-AUC scores

### Model Artifacts
- **`tsn_extended.keras`**: Keras/TensorFlow model (Python training artifact)
- **`tsn_extended_norm.json`**: Feature normalization statistics (`mean`, `std`, `feature_order`)
- **`tsn_extended_fdeep.json`**: Frugally-Deep C++ model for real-time inference
- **Training artifacts**: `history.json`, `metrics.json`, validation reports

### Model Conversion Pipeline
- **Keras → Frugally-Deep**: `scripts/convert_to_frugally_deep.py`
- **Validation**: `scripts/audit_trainer.py` ensures model equivalence
- **Performance**: Sub-millisecond inference suitable for 1ms TSN windows

## In-Simulation Inference

**Real-time ML classification** integrated into simulation loop:

### Configuration (`simulations/omnetpp.ini`)
```ini
# Model paths (relative to simulation directory)
*.mlInferenceEngine.modelPath = "../ml_models/tsn_extended_fdeep.json"
*.mlInferenceEngine.normPath  = "../ml_models/tsn_extended_norm.json"
*.mlInferenceEngine.inferenceInterval = 1ms
*.mlInferenceEngine.anomalyThreshold = 0.7

# Vector recording for inference results
**.inferenceResult:vector.result-recording-modes = all
**.inferenceResult:vector.vector-recording = true
```

### Inference Process
- **1ms intervals**: Synchronized with data collection windows
- **Feature extraction**: Pulls aggregated features from DataCollector module
- **Preprocessing**: Missing value imputation (-1 → NaN → 0), z-score normalization
- **Classification**: Binary output (NORMAL/ANOMALY) with probability scores
- **Real-time logging**: `inference_*.csv` with timestamps and feature values

### Integration Features
- **Signal emission**: `inferenceResult` signal for OMNeT++ vector recording
- **Display updates**: Module display string shows current classification
- **Performance tracking**: Inference latency measurement and statistics
- **Attack detection**: State management for attack classification

## Validation Checklist

**Post-run verification** for data quality and model performance:

### Expected Output Counts
- **`window_features_*`**: 500 rows per run (0–499ms, one per 1ms window)
- **`tsn_signals_*`**: Variable rows depending on packet volume (~1000-5000 packets per run)
- **`inference_*`**: 500 rows per run matching window features

### Scenario-Specific Patterns
- **Baseline**: `drop_rate≈0`, `queue_length_max` < 10, ~50 windows with gPTP timing data
- **DoSAttack**: Elevated `drop_rate` (0.1-0.3), high `queue_length_max`, attack timing matches 100-400ms window
- **TimingAttack**: Clock drift effects, PCP6 gate starvation, sparse gPTP samples due to timing disruption
- **SpoofingAttack**: Impostor traffic with PCP7/VLAN10 encoding, timing matches 150-350ms window

### Data Quality Indicators
- **gPTP sparsity**: `peer_delay_mean` missing in most windows expected due to 50ms cadence
- **E2E timing**: Present only when application traffic flows (not all windows)
- **Sample counters**: `ptp_samples`, `e2e_samples` indicate data availability per window

## Implementation Notes

### Signal Subscription Strategy
- **Direct signal access** via `findSignal()` rather than separate registration
- **Module hierarchy traversal** to locate signal sources across network topology
- **Path-based parsing** for extracting port/gate indices from module paths

### Missing Value Semantics
- **`-1` values**: Explicit "no data available" indicator (preferred format)
- **Zero values**: Legacy format when no samples present (still supported)
- **Training compatibility**: Models handle both formats using sample counters

### Performance Considerations
- **1ms windows**: Balances temporal resolution with computational feasibility
- **Sparse features**: gPTP timing data available ~10% of windows due to 50ms cadence
- **Inference latency**: Sub-millisecond target for real-time TSN requirements
- **Memory management**: Fixed-size feature buffers prevent unbounded growth

## Dependencies

### Paths

- **INET 4.5** - OMNeT++ network simulation framework
- **Eigen 3.4.0** - Linear algebra library for matrix operations
- **frugally-deep** - Header-only C++ neural network inference library
- **json-develop** - JSON parsing library for model configuration
- **FunctionalPlus** - Functional programming utilities for C++

### Python Environment

**ML Training Dependencies** (conda environment `tf-omnet`):

- **TensorFlow** - Deep learning framework for neural network training
- **Keras** - High-level neural network API
- **scikit-learn** - Machine learning utilities (train_test_split, metrics, preprocessing)
- **pandas** - Data manipulation and CSV processing
- **numpy** - Numerical computing and array operations
- **frugally-deep** - Python bindings for model conversion

**Installation command**:
```bash
conda run -n tf-omnet python scripts/train_tsn_extended_model.py
```

### Build System

**OMNeT++ Requirements**:
- **OMNeT++ 6.1+** - Discrete event simulation framework
- **C++ compiler** - Clang/GCC with C++17 support
- **CMake/Make** - Build system configuration

**Platform-specific paths** are automatically detected in `makefrag` for Windows/Linux compatibility.

## License

Project code for academic use; INET and related frameworks retain their own licenses.

---
