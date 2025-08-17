# TSN ML Integration Scripts

This directory contains scripts for the TSN ML integration project, focusing on real-time anomaly detection in Time-Sensitive Networks.

## Current Approach

The current approach focuses on **5 key metrics** for ML-based intrusion detection:

1. **End-to-end delay**: Measures packet transmission time from source to destination
2. **Throughput**: Measures network bandwidth utilization
3. **Queue length**: Monitors buffer utilization at switches
4. **Packet drop rate**: Tracks packet loss in the network
5. **Total packets**: Monitors overall traffic volume

## Workflow

1. **Data Collection**: Metrics are collected directly from OMNeT++ simulation results (`.vec` files)
2. **Model Training**: A focused ML model is trained using only the 5 key metrics
3. **Model Export**: The trained model is exported to frugally-deep compatible JSON format
4. **Real-time Inference**: The model is used for real-time inference in the C++ simulation

## Active Scripts

### `comprehensive_tsn_extractor.py` (MAIN SCRIPT)
**Optimized multi-threaded TSN metrics extractor** - This is the primary extraction script.

Features:
- Pre-filters vectors for 10-50x performance improvement
- Optimized for 64GB RAM systems with smart multiprocessing
- Streaming intermediate saves for safety
- Outputs to `CSVextractions/` directory
- Processes all TSN metrics categories in parallel

Usage:
```bash
python3 comprehensive_tsn_extractor.py --input simulations/results --output simulations/results/CSVextractions
```

### `tsn_focused_ml.py`
Script for extracting the 5 key metrics and training the ML model

### `model_converter.py` 
Utility for converting Keras models to frugally-deep format

## Backup Files

- `fast_tsn_extractor.py.BACKUP`: Previous fast extraction script (disabled to avoid confusion)
- Results from fast extraction are stored in `../simulations/results/FastExtractions_BACKUP/`

## Usage

To extract metrics and train the model:

```bash
# 1. Extract metrics (main script - optimized)
python3 comprehensive_tsn_extractor.py

# 2. Train ML model
python3 tsn_focused_ml.py
```

This will:
1. Extract all TSN metrics from simulation results efficiently
2. Train a model using the key metrics
3. Export the model to the `../ml_models/` directory 