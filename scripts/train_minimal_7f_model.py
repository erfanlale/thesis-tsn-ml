#!/usr/bin/env python3
"""
Train a TSN classifier with extended timing/servo features and export to frugally-deep JSON.

Schema highlights (window_features_*.csv):
- Base: throughput_bps_tx, throughput_bps_rx, packets_sent, packets_received, packets_dropped, drop_rate, queue_length_max
- Servo: ptp_offset_mean, ptp_offset_max, rate_ratio_mean, peer_delay_mean
- Receiver timing: e2e_delay_avg, e2e_delay_max, e2e_delay_std
- Sample counters: ptp_samples, e2e_samples (used for masking sparse windows)

Label: anomaly = (label != 'normal')
Split: by file (all rows from a file stay together) to avoid leakage
Normalization: z-score using training mean/std (saved alongside model)
"""
import os
import sys
import subprocess
import shutil
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
    candidates: list[Path] = []
    # Prefer new window-level features
    candidates += list((root / 'results_flat').glob('window_features_*.csv'))
    candidates += list((root / 'simulations' / 'results_flat').glob('window_features_*.csv'))
    # Backward-compat: also allow tsn_signals_*.windows.csv if present
    candidates += list((root / 'results_flat').glob('tsn_signals_*.windows.csv'))
    candidates += list((root / 'simulations' / 'results_flat').glob('tsn_signals_*.windows.csv'))
    # de-dup
    uniq: list[Path] = []
    seen: set[Path] = set()
    for p in candidates:
        if p.exists() and p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


REQUIRED_COLS = {
    'throughput_bps_tx','throughput_bps_rx',
    'packets_sent','packets_received','packets_dropped',
    'queue_length_max',
    # timing features are optional but preferred; we will mask if missing in a row
}


def load_files(files: list[Path]) -> pd.DataFrame:
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df['__file__'] = str(f)
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


def build_dataset(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    # Ensure base required columns
    base = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped',
        'queue_length_max'
    ]
    for c in base:
        if c not in df.columns:
            raise RuntimeError(f"Missing required column: {c}")

    # Derive drop_rate if missing
    if 'drop_rate' not in df.columns:
        total = (df['packets_sent'].astype(float)
                 + df['packets_received'].astype(float)
                 + df['packets_dropped'].astype(float))
        df = df.assign(drop_rate=np.where(total > 0.0, df['packets_dropped'].astype(float) / total, 0.0))

    # Timing columns (may be NA = -1.0 by design). Convert -1.0 to NaN for masking.
    timing_cols = ['ptp_offset_mean','ptp_offset_max','rate_ratio_mean','peer_delay_mean',
                   'e2e_delay_avg','e2e_delay_max','e2e_delay_std']
    for c in timing_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')
            df.loc[df[c] == -1.0, c] = np.nan

    # Sample counters for masks (optional)
    has_ptp_col = 'ptp_samples' in df.columns
    has_e2e_col = 'e2e_samples' in df.columns
    if has_ptp_col:
        df['has_ptp'] = (pd.to_numeric(df['ptp_samples'], errors='coerce').fillna(0) > 0).astype(int)
    else:
        df['has_ptp'] = (~df[timing_cols[:3]].isna().all(axis=1)).astype(int) if set(timing_cols[:3]).issubset(df.columns) else 0
    if has_e2e_col:
        df['has_e2e'] = (pd.to_numeric(df['e2e_samples'], errors='coerce').fillna(0) > 0).astype(int)
    else:
        df['has_e2e'] = (~df[['e2e_delay_avg','e2e_delay_max','e2e_delay_std']].isna().all(axis=1)).astype(int) if set(['e2e_delay_avg','e2e_delay_max','e2e_delay_std']).issubset(df.columns) else 0

    # Final feature list: base + drop_rate + timing + masks
    feats = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped','drop_rate',
        'queue_length_max',
        'ptp_offset_mean','ptp_offset_max','rate_ratio_mean','peer_delay_mean',
        'e2e_delay_avg','e2e_delay_max','e2e_delay_std',
        'has_ptp','has_e2e'
    ]
    present = [c for c in feats if c in df.columns]

    # Labels
    if 'label' not in df.columns:
        raise RuntimeError('Missing label column')
    y_all = (df['label'].astype(str) != 'normal').astype(int)

    # Numeric conversion and row filtering: keep rows with at least base features present; allow NaNs in timing
    df_num = df.copy()
    for c in present:
        df_num[c] = pd.to_numeric(df_num[c], errors='coerce')
    # Drop rows where base or drop_rate missing
    base_req = ['throughput_bps_tx','throughput_bps_rx','packets_sent','packets_received','packets_dropped','drop_rate','queue_length_max']
    keep = df_num[base_req].replace([np.inf, -np.inf], np.nan).dropna().index
    df_num = df_num.loc[keep]
    y = y_all.loc[keep].to_numpy()
    files = df.loc[keep, '__file__'].tolist()
    X = df_num[present].to_numpy()
    return X, y, files, present


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
    mean = np.nanmean(Xtr, axis=0)
    std = np.nanstd(Xtr, axis=0)
    std = np.where(std == 0.0, 1.0, std)
    # Replace remaining NaNs with zeros for stable training (after masking these columns by has_* signals)
    mean = np.where(np.isnan(mean), 0.0, mean)
    std = np.where(np.isnan(std), 1.0, std)
    return mean, std


def zscore_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return (X - mean) / std


def build_model(input_dim: int) -> keras.Model:
    inp = layers.Input(shape=(input_dim,), name='in')
    x = layers.Dense(32, activation='relu', name='dense1')(inp)
    x = layers.Dense(16, activation='relu', name='dense2')(x)
    out = layers.Dense(2, activation='softmax', name='out')(x)
    model = keras.Model(inputs=inp, outputs=out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss='sparse_categorical_crossentropy',
                  metrics=['accuracy'])
    return model


def main():
    root = Path(__file__).resolve().parents[1]
    out_dir = root / 'ml_models'
    out_dir.mkdir(parents=True, exist_ok=True)

    files = find_csvs(root)
    print(f"Found {len(files)} CSV files")
    df = load_files(files)
    X, y, file_keys, feature_order = build_dataset(df)
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
    keras_path = out_dir / 'tsn_extended.keras'
    model.save(keras_path)

    # Save normalization stats
    stats = {
        'feature_order': feature_order,
        'mean': mean.tolist(),
        'std': std.tolist(),
    }
    (out_dir / 'tsn_extended_norm.json').write_text(json.dumps(stats, indent=2))

    # Convert to frugally-deep JSON using the SAME Python interpreter
    # This ensures we use the conda env (tf-omnet) and not the OMNeT++ venv
    converter_driver = root / 'scripts' / 'convert_to_frugally_deep.py'
    fdeep_json = out_dir / 'tsn_extended_fdeep.json'
    try:
        conda = shutil.which('conda')
        if conda:
            cmd = [conda, 'run', '-n', 'tf-omnet', 'python', str(converter_driver), str(keras_path), str(fdeep_json), '--no-tests']
        else:
            cmd = [sys.executable, str(converter_driver), str(keras_path), str(fdeep_json), '--no-tests']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Frugally-deep conversion failed (non-zero exit). Command: {e}")
    if not fdeep_json.exists():
        raise RuntimeError(f"Frugally-deep JSON not created at {fdeep_json}")

    print('Saved:')
    print('  Keras model:', keras_path)
    print('  fdeep JSON :', fdeep_json)
    print('  Norm stats :', out_dir / 'tsn_extended_norm.json')


if __name__ == '__main__':
    main()


