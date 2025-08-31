# MinimalPSFP Scenario: Implementation Status Report

*Generated: $(date)*  
*Status: Implementation Complete - CSV Schema Optimized for ML*

## Overview

The MinimalPSFP scenario is a 7-node TSN testbed with a central `TsnSwitch`, end stations, and two attack nodes. Topology and ML components are declared in `simulations/MinimalAttackNetwork.ned`:

```29:36:simulations/MinimalAttackNetwork.ned
        // ML Feature Collector - ENABLED for real-time data collection
        dataCollector: DataCollector {
            @display("p=50,350;i=block/process");
        }
        
        // ML Inference Engine
        mlInferenceEngine: TSNMLInferenceEngine {
            @display("p=50,250;i=block/cogwheel");
        }
```

## Configuration

Runs are configured in `simulations/omnetpp.ini` with PSFP, Qbv, and ML parameters. DataCollector emits CSV to `results_flat/tsn_signals_${configname}-#${repetition}.csv`, 1ms windowing:

```419:428:simulations/omnetpp.ini
# ---- DATA COLLECTOR CONFIGURATION ----
# Configure DataCollector for time-windowed CSV output optimized for ML
*.dataCollector.outputFile = "results_flat/tsn_signals_${configname}-#${repetition}.csv"
*.dataCollector.windowLength = 1ms
*.dataCollector.emitCSV = true
*.dataCollector.emitPCPBreakdowns = false
*.dataCollector.emitRaw = false
*.dataCollector.emitNDJSON = false
*.dataCollector.emitPerStreamRows = true
```

## ML Integration

The ML inference engine expects the same minimal 7 features as training, explicitly listed in code:

```44:49:src/TSNMLInferenceEngine.cc
    // Minimal 7-feature order used by training/inference (F7)
    // [throughput_bps_tx, throughput_bps_rx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max]
    feature_columns = {
        "throughput_bps_tx","throughput_bps_rx",
        "packets_sent","packets_received","packets_dropped","drop_rate",
        "queue_length_max"
    };
```

## DataCollector: Before → After (What Changed and Why)

### Before (Legacy Schema)
The previous per-packet CSV header included redundant and leaky columns:
- `streamHandle` (duplicate of `streamName`)
- `srcNode/dstNode` strings (redundant with MAC addresses)
- Per-port counters `txPk_node/rxPk_node` (time/progress leakage)
- Free-text `reason` field (redundant with `meter_filtered`)

### After (Current Schema)
Trimmed, numeric, and non-leaky; single stream identifier and no free-text reason:

```505:512:src/DataCollector.cc
    // Canonical per-packet schema for tsn_signals_*.csv (egress rows + filter-drop rows)
    std::vector<std::string> header = {
        "run","t","streamName",
        "srcMACdec","dstMACdec","pcp","vid","lenB","qLenBits",
        "gateState","meter_conform","meter_exceed","meter_filtered"
    };
    csv.setHeader(header);
```

### Evidence from Generated Baseline Run

**Per-packet CSV (tsn_signals_Baseline-#0.csv):**
```1:3:results_flat/tsn_signals_Baseline-#0.csv
run,t,streamName,srcMACdec,dstMACdec,pcp,vid,lenB,qLenBits,gateState,meter_conform,meter_exceed,meter_filtered
Baseline-#0,0.000000000,0A-AA-00-00-00-02->01-80-C2-00-00-0E,11725260718082,1652522221582,0,0,72,0,0,0,0,0
Baseline-#0,0.000002050,0A-AA-00-00-00-08->0A-AA-00-00-00-0A,11725260718088,11725260718090,5,30,150,0,0,1,0,0
```

## Schema Changes Details

### Stream Identity
- **Before**: `streamName` + `streamHandle` (duplicate)
- **After**: `streamName` only

### Node Identity
- **Before**: `srcNode/dstNode` strings + `srcMACdec/dstMACdec` numbers
- **After**: MAC decimals only (satisfies "map nodes to numeric IDs and drop strings")

### Per-Port Counters
- **Before**: `txPk_node/rxPk_node` included
- **After**: Removed to eliminate time/progress leakage
- **Note**: If deltas are needed, compute from window-level CSVs during preprocessing

### Meter Fields
- **Before**: `meter_conform`, `meter_exceed`, `meter_filtered`, `reason`
- **After**: Numeric triplet only; `reason` removed (redundant with `meter_filtered=1`)

Mapping implementation:
```1070:1079:src/DataCollector.cc
            int meter_conform = (color==0) ? 1 : 0;
            int meter_exceed = (color==1 || color==2) ? 1 : 0;
            int meter_filtered = filteredTreeIds.count(packet->getTreeId()) ? 1 : 0;
            std::string reason = "";
            auto itR = dropReasonByTreeId.find(packet->getTreeId());
            if (itR != dropReasonByTreeId.end()) reason = itR->second;
```

### Gate State Normalization
- **Egress rows**: 0/1 from actual TAS gate state
- **Filter-only rows** (no vantage): emit sentinel -1 to denote N/A (avoid fabricating 0)

```1125:1139:src/DataCollector.cc
            csv.newRow();
            const std::string runId = currentConfigName + "-#" + std::to_string(currentRepetition);
            csv.add(runId);                 // run
            csv.add(ts);                    // t [s]
            csv.add(streamId);              // streamName
            csv.add((long)srcMacDec);       // srcMACdec
            csv.add((long)dstMacDec);       // dstMACdec
            csv.add(pcpVal<0?0:pcpVal);     // pcp
            csv.add(vlanIdCsv<0?0:vlanIdCsv); // vid
            csv.add((long)lenB);            // lenB [bytes]
            csv.add(qBits);                 // qLenBits [bits]
            csv.add(gateState);             // gateState 0/1
            csv.add(meter_conform);         // meter_conform
            csv.add(meter_exceed);          // meter_exceed
            csv.add(meter_filtered);        // meter_filtered
```

```900:907:src/DataCollector.cc
                csv.add((long)bytes2);        // lenB
                csv.add(-1L);                 // qLenBits N/A
                csv.add(-1);                  // gateState N/A (sentinel)
                csv.add(color2==0 ? 1 : 0);   // meter_conform
                csv.add((color2==1 || color2==2) ? 1 : (color2<0 ? -1 : 0)); // meter_exceed
                csv.add(1);                   // meter_filtered
```

**Preprocessing Guidance**: Treat -1 as missing (mask/impute to training mean or add binary "gateState_missing" indicator). This avoids skewing feature means (e.g., -0.747).

### PCP/VID Non-Negative (DoS Artifact Leakage Removed)
```884:885:src/DataCollector.cc
                if (pcpVal2 < 0) pcpVal2 = 0;
                if (vlan2 < 0) vlan2 = 0;
```

And for egress:
```1131:1134:src/DataCollector.cc
            csv.add(pcpVal<0?0:pcpVal);     // pcp
            csv.add(vlanIdCsv<0?0:vlanIdCsv); // vid
```

### Duplicate Rows Caveat (Vantage Restriction)
- Write egress rows only on central switch, port-scoped vantage
- Reduces over-counting
- Vantage configured in code:

```159:161:src/DataCollector.h
    std::string vantageMacPrefix = "MinimalAttackNetwork.centralSwitch.eth[4].mac";
    std::string vantageQueuePrefix = "MinimalAttackNetwork.centralSwitch.eth[4].macLayer.queue";
    const std::string centralSwitchMeterPrefix = "MinimalAttackNetwork.centralSwitch.bridging.streamFilter.ingress.meter";
```

**Note**: A single logical packet can still have multiple egresses in certain topologies; restricting to central switch egress is intentional to prevent overweighting across devices.

## New: Window-Level CSV for Training

DataCollector now writes a second file `results_flat/window_features_${configname}-#${repetition}.csv` per 1ms window with the 7 training features + label, and includes gPTP servo and receiver-side timing observables.

### File Naming and Header
```257:268:src/DataCollector.cc
        size_t sigpos = windowFile.find("tsn_signals_");
        if (sigpos != std::string::npos) {
            windowFile.replace(sigpos, std::string("tsn_signals_").size(), "window_features_");
        } else {
            // Fallback: append .windows before extension
            size_t dotp = windowFile.rfind('.');
            if (dotp != std::string::npos) windowFile.insert(dotp, ".windows");
            else windowFile += ".windows.csv";
        }
```

```269:282:src/DataCollector.cc
        // Header aligned with training pipeline expectations + servo/sink observables
        streamCsv.setHeader({
            "throughput_bps_tx","throughput_bps_rx",
            "packets_sent","packets_received","packets_dropped",
            "drop_rate","queue_length_max",
            // gPTP servo observables (per-window aggregates)
            "ptp_offset_mean","ptp_offset_max","rate_ratio_mean","peer_delay_mean",
            // Receiver-side timing outcomes
            "e2e_delay_avg","e2e_delay_max","e2e_delay_std",
            // Label last
            "label"
        });
```

### Window Writer in `flushCurrentWindow()`
```479:507:src/DataCollector.cc
void DataCollector::flushCurrentWindow()
{
    // Window-level CSV write (secondary file)
    if (emitCSV) {
        double t1 = SIMTIME_DBL(simTime());
        double dur = t1 - currentWindowStart;
        if (dur > 1e-12) {
            double thrTx = (dur > 0) ? ((double)w_txBits / dur) : 0.0;
            double thrRx = (dur > 0) ? ((double)w_rxBits / dur) : 0.0;
            long sent = (long)w_packetsSent;
            long received = (long)w_packetsReceived;
            long dropped = (long)w_packetsDropped;
            double denom = (double)sent + (double)received + (double)dropped;
            double dropRate = denom > 0.0 ? ((double)dropped / denom) : 0.0;
            long qlenMax = (long)w_queueLenMax;
            // gPTP servo aggregates (means over events in the window)
            double offsetMean = (w_gptpOffsetCount>0) ? (w_gptpOffsetSum / (double)w_gptpOffsetCount) : 0.0;
            double offsetMax  = w_gptpOffsetMax;
            double rateMean   = (w_rateRatioCount>0) ? (w_rateRatioSum / (double)w_rateRatioCount) : 0.0;
            double pdelayMean = (w_peerDelayCount>0) ? (w_peerDelaySum / (double)w_peerDelayCount) : 0.0;
            // Receiver-side e2e stats
            double e2eAvg = (w_sinkE2eCount>0) ? (w_sinkE2eSum / (double)w_sinkE2eCount) : 0.0;
            double e2eMax = w_sinkE2eMax;
            double e2eStd = 0.0;
            if (w_sinkE2eCount>1) {
                double mean = e2eAvg;
                double var = std::max(0.0, (w_sinkE2eSumSq / (double)w_sinkE2eCount) - mean*mean);
                e2eStd = std::sqrt(var);
            }
            std::string label = determineLabelForWindow(currentWindowStart, t1);
            streamCsv.newRow();
            streamCsv.add(thrTx);
            streamCsv.add(thrRx);
            streamCsv.add((double)sent);
            streamCsv.add((double)received);
            streamCsv.add((double)dropped);
            streamCsv.add(dropRate);
            streamCsv.add((double)qlenMax);
            streamCsv.add(offsetMean);
            streamCsv.add(offsetMax);
            streamCsv.add(rateMean);
            streamCsv.add(pdelayMean);
            streamCsv.add(e2eAvg);
            streamCsv.add(e2eMax);
            streamCsv.add(e2eStd);
            streamCsv.add(label);
            streamCsv.writeToFile();
        }
    }
    // ... existing code ...
}
```

### Evidence from Generated Baseline Run

**Window features CSV (window_features_Baseline-#0.csv):**
```1:3:results_flat/window_features_Baseline-#0.csv
throughput_bps_tx,throughput_bps_rx,packets_sent,packets_received,packets_dropped,drop_rate,queue_length_max,ptp_offset_mean,ptp_offset_max,rate_ratio_mean,peer_delay_mean,e2e_delay_avg,e2e_delay_max,e2e_delay_std,label
0.000000000,0.000000000,5.000000000,1.000000000,0.000000000,0.000000000,2.000000000,0.000000000,0.000000000,0.000000000,0.000000000,0.000000000,0.000000000,0.000000000,normal
```

## Training Pipeline Alignment

The trainer now searches for `window_features_*.csv` (with backward-compat for `*.windows.csv`). This ensures the trainer consumes the aggregated 7-feature windows, not per-packet rows. The inference engine already consumes the same 7 features (see citation above).

**Note**: No training claims are made here; run the trainer to produce logs if needed.

## PSFP and Traffic Configuration (INI Highlights)

Streams are encoded/decoded and classified per PSFP, with gPTP identification and a fail-closed default path. Dual-rate three-color meters (green/yellow/red) and drop policy configured. Qbv gates per traffic class with periodic schedules.

### Attack Scenarios
- **DoS flooding**: 100-400 ms, 1500B at 5 µs intervals
- **Timing attack**: Drift + tight gPTP gate
- **Spoofing**: PCP/VLAN match to critical stream, higher rate

These are all explicit in `simulations/omnetpp.ini` (see earlier excerpt and surrounding lines for meter/gate settings).

## Build and Run

### Build
```bash
make -j$(nproc)
```

### Run Examples
```bash
# Baseline
./MinimalPSFP-Attack-ML -u Cmdenv -n .:src:simulations:/media/eriloo/SharedRoom1/omnetpp-ml-workspace/inet4.5/src -c Baseline -r 0 -f simulations/omnetpp.ini

# DoS Attack
./MinimalPSFP-Attack-ML -u Cmdenv -n .:src:simulations:/media/eriloo/SharedRoom1/omnetpp-ml-workspace/inet4.5/src -c DoSAttack -r 0 -f simulations/omnetpp.ini
```

## What to Expect in results_flat

- **Per-packet egress rows**: `tsn_signals_${config}-#${rep}.csv` with the new, slimmed header
- **Window features for ML**: `window_features_${config}-#${rep}.csv`

## Notes and Guidance

### Gate State Preprocessing
Impute -1 as missing (not zero), or add a mask column. This avoids biased normalization.

### Class Balancing/Duplication
Vantage restricted to central switch egress to limit overweighting. If stricter de-duplication is required, we can add an optional INI flag later to keep only one egress port per packet treeId.

### PCP/VID
Never negative; extracted from tags or 802.1Q header; fallback to 0 if absent.

### Timing Observables (new)
- **gPTP servo**: `ptp_offset_mean`, `ptp_offset_max`, `rate_ratio_mean`, `peer_delay_mean` are aggregated per window from INET `**.gptp` signals (`timeDifference`, `rateRatio`, `peerDelay`).
- **Receiver timing**: `e2e_delay_avg`, `e2e_delay_max`, `e2e_delay_std` are derived at application sinks using `packetReceived` with `CreationTimeTag`.

## Before → After Summary (DataCollector)

| Aspect | Before | After |
|--------|--------|-------|
| **Stream Identity** | `streamName` + `streamHandle` | `streamName` only |
| **Node Identity** | `srcNode/dstNode` strings + MAC decimals | MAC decimals only |
| **Per-Port Counters** | `txPk_node/rxPk_node` included | Removed (non-ML-safe) |
| **Meter/Drop Explanation** | `meter_conform`, `meter_exceed`, `meter_filtered`, `reason` | Numeric triplet only (no reason) |
| **Gate State** | Mixed comment/values | 0/1 at egress; -1 sentinel on filter-only rows |
| **PCP/VID** | Occasional -1 during DoS | Extraction fixed; fallback to 0 to avoid leakage |
| **Duplication** | Multiple vantage points possible | Restricted to central switch egress |

## Implementation Status

✅ **Completed**
- CSV schema slimming and optimization
- PCP/VID non-negative extraction
- Gate state normalization with sentinel values
- Window-level CSV writer for ML training
- Training script alignment
- Build validation
- Baseline run validation

## File Locations

- **Source**: `src/DataCollector.cc`, `src/DataCollector.h`
- **Training**: `scripts/train_minimal_7f_model.py`
- **Configuration**: `simulations/omnetpp.ini`, `simulations/MinimalAttackNetwork.ned`
- **Results**: `results_flat/tsn_signals_*.csv`, `results_flat/window_features_*.csv`

All changes are implemented in `src/DataCollector.cc` and validated by a Baseline run producing both per-packet and window-level CSVs.
