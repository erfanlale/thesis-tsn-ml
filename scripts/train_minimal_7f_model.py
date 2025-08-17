#!/usr/bin/env python3
"""
Train a minimal 7-feature TSN classifier and export to frugally-deep JSON.

Feature order (locked):
F = [
  throughput_bps_tx, throughput_bps_rx,
  packets_sent, packets_received, packets_dropped, drop_rate,
  queue_length_max
]

Label: anomaly = (label != 'normal')
Split: by file (all rows from a file stay together) to avoid leakage
Normalization: z-score using training mean/std (saved alongside model)
"""
import os
import sys
import subprocess
import glob
import json
from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Use standalone Keras 3 API per frugally-deep requirements
import keras
from keras import layers


def find_csvs(root: Path) -> list[Path]:
    # Unified location per user's request
    candidates = list((root / 'simulations' / 'results').glob('tsn_signals_*.csv'))
    return [p for p in candidates if p.exists()]


REQUIRED_COLS = {
    'throughput_bps_tx','throughput_bps_rx',
    'packets_sent','packets_received','packets_dropped',
    'queue_length_max','drop_rate'
}


def load_files(files: list[Path]) -> pd.DataFrame:
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df['__file__'] = str(f)
            # keep only window rows
            if 'name' in df.columns:
                df = df[df['name'] == 'windowFeatures']
            # skip files lacking required columns
            if not REQUIRED_COLS.issubset(set(df.columns)):
                print(f"SKIP (schema): {f}")
                continue
            dfs.append(df)
        except Exception as e:
            print(f"WARN: failed to read {f}: {e}")
    if not dfs:
        raise RuntimeError('No CSV files loaded')
    return pd.concat(dfs, ignore_index=True)


def build_dataset(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    # Required columns
    required = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped',
        'queue_length_max'
    ]
    for c in required:
        if c not in df.columns:
            raise RuntimeError(f"Missing required column: {c}")

    # drop_rate must be present in unified schema

    # queue_length_avg dropped from schema; we train without it (7 features total)

    # label → anomaly (1) vs normal (0)
    if 'label' not in df.columns:
        raise RuntimeError('Missing label column')
    y = (df['label'].astype(str) != 'normal').astype(int).to_numpy()

    # keep rows with finite features only
    feats = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped','drop_rate',
        'queue_length_max'
    ]
    X = df[feats].astype(float).replace([np.inf, -np.inf], np.nan).dropna().to_numpy()
    # align y
    y = y[df[feats].astype(float).replace([np.inf, -np.inf], np.nan).dropna().index]
    files = df.loc[df[feats].astype(float).replace([np.inf, -np.inf], np.nan).dropna().index, '__file__'].tolist()
    return X, y, files


def split_by_file(X, y, files):
    file_list = np.array(files)
    unique_files = np.unique(file_list)
    if len(unique_files) >= 3:
        train_files, test_files = train_test_split(unique_files, test_size=0.3, random_state=42)
        train_mask = np.isin(file_list, train_files)
        test_mask = np.isin(file_list, test_files)
        return (X[train_mask], y[train_mask]), (X[test_mask], y[test_mask])
    elif len(unique_files) == 2:
        # 50/50 split by file
        train_files, test_files = [unique_files[0:1]], [unique_files[1:2]]
        train_mask = np.isin(file_list, train_files)
        test_mask = np.isin(file_list, test_files)
        return (X[train_mask], y[train_mask]), (X[test_mask], y[test_mask])
    else:
        # Fallback: stratified row-wise split
        return train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)


def zscore_fit(Xtr: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mean = Xtr.mean(axis=0)
    std = Xtr.std(axis=0)
    std = np.where(std == 0.0, 1.0, std)
    return mean, std


def zscore_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return (X - mean) / std


def build_model(input_dim: int) -> keras.Model:
    inp = layers.Input(shape=(input_dim,), name='in')
    x = layers.Dense(16, activation='relu', name='dense1')(inp)
    out = layers.Dense(2, activation='softmax', name='out')(x)
    model = keras.Model(inputs=inp, outputs=out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss='sparse_categorical_crossentropy',
                  metrics=['accuracy'])
    return model


def main():
    root = Path(__file__).resolve().parents[1]
    # Save trained artifacts into unified simulations/results as well
    out_dir = root / 'simulations' / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)

    files = find_csvs(root)
    print(f"Found {len(files)} CSV files")
    df = load_files(files)
    X, y, file_keys = build_dataset(df)
    (Xtr, ytr), (Xte, yte) = split_by_file(X, y, file_keys)

    mean, std = zscore_fit(Xtr)
    Xtr_n = zscore_apply(Xtr, mean, std)
    Xte_n = zscore_apply(Xte, mean, std)

    model = build_model(Xtr_n.shape[1])
    model.fit(Xtr_n, ytr, epochs=20, batch_size=64, verbose=0,
              validation_data=(Xte_n, yte))

    # Evaluate
    yprob = model.predict(Xte_n, verbose=0)
    ypred = np.argmax(yprob, axis=1)
    print('Test report:\n', classification_report(yte, ypred, digits=4))
    print('Confusion matrix:\n', confusion_matrix(yte, ypred))

    # Save Keras
    keras_path = out_dir / 'tsn_minimal7.keras'
    model.save(keras_path)

    # Save normalization stats
    stats = {
        'feature_order': [
            'throughput_bps_tx','throughput_bps_rx','packets_sent','packets_received',
            'packets_dropped','drop_rate','queue_length_max'
        ],
        'mean': mean.tolist(),
        'std': std.tolist(),
    }
    (out_dir / 'tsn_minimal7_norm.json').write_text(json.dumps(stats, indent=2))

    # Convert to frugally-deep JSON using the SAME Python interpreter
    # This ensures we use the conda env (tf-omnet) and not the OMNeT++ venv
    converter_driver = root / 'scripts' / 'convert_to_frugally_deep.py'
    fdeep_json = out_dir / 'tsn_minimal7_fdeep.json'
    try:
        subprocess.run([sys.executable, str(converter_driver), str(keras_path), str(fdeep_json), '--no-tests'], check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Frugally-deep conversion failed (non-zero exit). Command: {e}")
    if not fdeep_json.exists():
        raise RuntimeError(f"Frugally-deep JSON not created at {fdeep_json}")

    print('Saved:')
    print('  Keras model:', keras_path)
    print('  fdeep JSON :', fdeep_json)
    print('  Norm stats :', out_dir / 'tsn_minimal7_norm.json')


if __name__ == '__main__':
    main()


