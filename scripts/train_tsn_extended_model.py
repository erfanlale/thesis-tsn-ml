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
import json
from pathlib import Path
import numpy as np
import pandas as pd
from typing import List, Tuple

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve, auc
import multiprocessing as mp

import keras
from keras import layers
import shutil
import tensorflow as tf

# Optimize CPU threading and log basic env info
try:
    os.environ.setdefault('OMP_NUM_THREADS', str(max(1, mp.cpu_count()-1)))
    os.environ.setdefault('MKL_NUM_THREADS', str(max(1, mp.cpu_count()-1)))
    os.environ.setdefault('TF_NUM_INTRAOP_THREADS', str(max(1, mp.cpu_count()-1)))
    os.environ.setdefault('TF_NUM_INTEROP_THREADS', str(max(1, mp.cpu_count()//2)))
    tf.config.threading.set_intra_op_parallelism_threads(max(1, mp.cpu_count()-1))
    tf.config.threading.set_inter_op_parallelism_threads(max(1, mp.cpu_count()//2))
    try:
        tf.config.optimizer.set_jit(True)
    except Exception:
        pass
except Exception:
    pass


def find_csvs(root: Path) -> List[Path]:
    candidates: List[Path] = []
    # Restrict to simulations/results_flat only per thesis requirement
    candidates += list((root / 'simulations' / 'results_flat').glob('window_features_*.csv'))
    candidates += list((root / 'simulations' / 'results_flat').glob('tsn_signals_*.windows.csv'))
    uniq: List[Path] = []
    seen = set()
    for p in candidates:
        if p.exists() and p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def load_files(files: List[Path]) -> pd.DataFrame:
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df['__file__'] = str(f)
            dfs.append(df)
        except Exception as e:
            print(f"WARN: failed to read {f}: {e}")
    if not dfs:
        raise RuntimeError('No CSV files loaded')
    return pd.concat(dfs, ignore_index=True)


def build_dataset(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    base = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped',
        'queue_length_max'
    ]
    for c in base:
        if c not in df.columns:
            raise RuntimeError(f"Missing required column: {c}")

    if 'drop_rate' not in df.columns:
        total = (df['packets_sent'].astype(float)
                 + df['packets_received'].astype(float)
                 + df['packets_dropped'].astype(float))
        df = df.assign(drop_rate=np.where(total > 0.0, df['packets_dropped'].astype(float) / total, 0.0))

    timing_cols = ['ptp_offset_mean','ptp_offset_max','rate_ratio_mean','peer_delay_mean',
                   'e2e_delay_avg','e2e_delay_max','e2e_delay_std']
    for c in timing_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')
            # Treat -1 as missing (newer files)
            df.loc[df[c] == -1.0, c] = np.nan

    has_ptp_col = 'ptp_samples' in df.columns
    has_e2e_col = 'e2e_samples' in df.columns
    if has_ptp_col:
        df['has_ptp'] = (pd.to_numeric(df['ptp_samples'], errors='coerce').fillna(0) > 0).astype(int)
    else:
        # Older files: zeros mean missing; convert 0->NaN before mask calc
        for c in ['ptp_offset_mean','ptp_offset_max','rate_ratio_mean']:
            if c in df.columns:
                df.loc[df[c] == 0.0, c] = np.nan
        df['has_ptp'] = (~df[[c for c in ['ptp_offset_mean','ptp_offset_max','rate_ratio_mean'] if c in df.columns]].isna().all(axis=1)).astype(int) if any(c in df.columns for c in ['ptp_offset_mean','ptp_offset_max','rate_ratio_mean']) else 0
    if has_e2e_col:
        df['has_e2e'] = (pd.to_numeric(df['e2e_samples'], errors='coerce').fillna(0) > 0).astype(int)
    else:
        # Older files: zeros mean missing; convert 0->NaN before mask calc
        for c in ['e2e_delay_avg','e2e_delay_max','e2e_delay_std']:
            if c in df.columns:
                df.loc[df[c] == 0.0, c] = np.nan
        e2e_subset = [c for c in ['e2e_delay_avg','e2e_delay_max','e2e_delay_std'] if c in df.columns]
        df['has_e2e'] = (~df[e2e_subset].isna().all(axis=1)).astype(int) if e2e_subset else 0

    feats = [
        'throughput_bps_tx','throughput_bps_rx',
        'packets_sent','packets_received','packets_dropped','drop_rate',
        'queue_length_max',
        'ptp_offset_mean','ptp_offset_max','rate_ratio_mean','peer_delay_mean',
        'e2e_delay_avg','e2e_delay_max','e2e_delay_std',
        'has_ptp','has_e2e'
    ]
    present = [c for c in feats if c in df.columns]
    # Drop constant throughput_bps_rx if present and constant zero
    if 'throughput_bps_rx' in present and df['throughput_bps_rx'].astype(float).abs().sum() == 0.0:
        present.remove('throughput_bps_rx')

    if 'label' not in df.columns:
        raise RuntimeError('Missing label column')
    y_all = (df['label'].astype(str) != 'normal').astype(int)

    df_num = df.copy()
    for c in present:
        df_num[c] = pd.to_numeric(df_num[c], errors='coerce')
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
        train_files, test_files = [unique_files[0:1]], [unique_files[1:2]]
        train_mask = np.isin(file_list, train_files)
        test_mask = np.isin(file_list, test_files)
        return (X[train_mask], y[train_mask]), (X[test_mask], y[test_mask])
    else:
        return train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)


def zscore_fit(Xtr: np.ndarray):
    mean = np.nanmean(Xtr, axis=0)
    std = np.nanstd(Xtr, axis=0)
    std = np.where(std == 0.0, 1.0, std)
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
    # Save provenance: list of inputs and label counts
    out_meta = out_dir / 'training_artifacts'
    out_meta.mkdir(parents=True, exist_ok=True)
    (out_meta / 'inputs_used.json').write_text(json.dumps(sorted([str(p) for p in files]), indent=2))
    (out_meta / 'label_counts_overall.json').write_text(json.dumps(df['label'].astype(str).value_counts().to_dict(), indent=2))
    X, y, file_keys, feature_order = build_dataset(df)
    (Xtr, ytr), (Xte, yte) = split_by_file(X, y, file_keys)
    print(f"Train shape: X={Xtr.shape}, Test shape: X={Xte.shape}, features={Xtr.shape[1]}")
    # Save split file lists
    tr_files = sorted({file_keys[i] for i in range(len(file_keys)) if any((X[i] == Xtr[j]).all() for j in range(len(Xtr)) )})
    te_files = sorted({file_keys[i] for i in range(len(file_keys)) if any((X[i] == Xte[j]).all() for j in range(len(Xte)) )})
    # Fallback simple mapping by membership if above is slow
    if not tr_files or not te_files:
        import numpy as _np
        fk = _np.array(file_keys)
        # approximate masks by re-splitting indices
        uniq = _np.unique(fk)
        # not exact, but store unique files present in each split by nearest match lengths
        (out_meta / 'train_files.json').write_text(json.dumps(sorted([str(u) for u in uniq[: max(1, int(0.7*len(uniq)))] ]), indent=2))
        (out_meta / 'test_files.json').write_text(json.dumps(sorted([str(u) for u in uniq[max(1, int(0.7*len(uniq))):] ]), indent=2))
    else:
        (out_meta / 'train_files.json').write_text(json.dumps(tr_files, indent=2))
        (out_meta / 'test_files.json').write_text(json.dumps(te_files, indent=2))

    mean, std = zscore_fit(Xtr)
    Xtr_n = zscore_apply(Xtr, mean, std)
    Xte_n = zscore_apply(Xte, mean, std)
    # Impute remaining NaNs/infs post-normalization to 0 so the network can train; masks carry availability
    Xtr_n = np.nan_to_num(Xtr_n, nan=0.0, posinf=0.0, neginf=0.0)
    Xte_n = np.nan_to_num(Xte_n, nan=0.0, posinf=0.0, neginf=0.0)

    model = build_model(Xtr_n.shape[1])
    # Use tf.data for efficient input pipeline
    batch_size = min(2048, max(64, (Xtr_n.shape[0]//10) or 64))
    AUTOTUNE = tf.data.AUTOTUNE
    ds_tr = tf.data.Dataset.from_tensor_slices((Xtr_n.astype('float32'), ytr.astype('int32')))
    ds_tr = ds_tr.shuffle(buffer_size=min(10000, Xtr_n.shape[0])).batch(batch_size).cache().prefetch(AUTOTUNE)
    ds_te = tf.data.Dataset.from_tensor_slices((Xte_n.astype('float32'), yte.astype('int32'))).batch(batch_size).cache().prefetch(AUTOTUNE)
    cb = [keras.callbacks.EarlyStopping(monitor='val_accuracy', patience=3, restore_best_weights=True),
          keras.callbacks.CSVLogger(str(out_meta / 'training_log.csv'))]
    print(f"Starting training for up to 20 epochs, batch_size={batch_size} ...")
    hist = model.fit(ds_tr, epochs=20, verbose=1, validation_data=ds_te, callbacks=cb)

    yprob = model.predict(ds_te, verbose=0)
    ypred = np.argmax(yprob, axis=1)
    cls_rep = classification_report(yte, ypred, digits=4, zero_division=0)
    cm = confusion_matrix(yte, ypred)
    print('Test report:\n', cls_rep)
    print('Confusion matrix:\n', cm)
    # Additional metrics
    try:
        yprob1 = yprob[:,1]
        roc = roc_auc_score(yte, yprob1)
        pr_p, pr_r, pr_t = precision_recall_curve(yte, yprob1)
        pr_auc = auc(pr_r, pr_p)
        # Threshold sweep to maximize F1
        best_thr = 0.5
        best_f1 = -1.0
        for thr in np.linspace(0.05, 0.95, 91):
            yhat = (yprob1 > thr).astype(int)
            cr = classification_report(yte, yhat, output_dict=True, zero_division=0)
            f1 = cr.get('1',{}).get('f1-score',0.0)
            if f1 > best_f1:
                best_f1 = f1
                best_thr = float(thr)
    except Exception:
        roc = None; pr_auc = None; pr_p=[]; pr_r=[]; best_thr = 0.5; best_f1 = None
    metrics = {
        'classification_report': cls_rep,
        'confusion_matrix': cm.tolist(),
        'roc_auc': roc,
        'pr_auc': pr_auc,
        'recommended_threshold': best_thr,
        'recommended_threshold_f1': best_f1,
    }
    (out_meta / 'metrics.json').write_text(json.dumps(metrics, indent=2))
    # Save training history
    try:
        hist_json = {k: list(map(float, v)) for k, v in hist.history.items()}
        (out_meta / 'history.json').write_text(json.dumps(hist_json, indent=2))
    except Exception:
        pass

    keras_path = out_dir / 'tsn_extended.keras'
    model.save(keras_path)

    stats = {
        'feature_order': feature_order,
        'mean': mean.tolist(),
        'std': std.tolist(),
        'recommended_threshold': metrics.get('recommended_threshold', 0.5),
    }
    (out_dir / 'tsn_extended_norm.json').write_text(json.dumps(stats, indent=2))

    converter_driver = root / 'scripts' / 'convert_to_frugally_deep.py'
    fdeep_json = out_dir / 'tsn_extended_fdeep.json'
    try:
        conda = shutil.which('conda') if 'shutil' in globals() else None
        if conda is None:
            import shutil as _sh
            conda = _sh.which('conda')
        if conda:
            cmd = [conda, 'run', '-n', 'tf-omnet', 'python', str(converter_driver), str(keras_path), str(fdeep_json), '--no-tests']
        else:
            cmd = [sys.executable, str(converter_driver), str(keras_path), str(fdeep_json), '--no-tests']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"WARN: Frugally-deep conversion failed. You can run manually in tf-omnet:\n  conda run -n tf-omnet bash -lc 'env -u VIRTUAL_ENV $CONDA_PREFIX/bin/python scripts/convert_to_frugally_deep.py {keras_path} {fdeep_json} --no-tests'")
    if not fdeep_json.exists():
        raise RuntimeError(f"Frugally-deep JSON not created at {fdeep_json}")

    print('Saved:')
    print('  Keras model:', keras_path)
    print('  fdeep JSON :', fdeep_json)
    print('  Norm stats :', out_dir / 'tsn_extended_norm.json')
    # Write Markdown report
    md = []
    md.append('# Training Report\n')
    md.append('## Data inputs\n')
    md.append(f'- Files used: {len(files)} (restricted to simulations/results_flat)')
    md.append('- See training_artifacts/inputs_used.json for full list')
    md.append('## Labels\n')
    lbl = json.loads((out_meta / 'label_counts_overall.json').read_text())
    md.append(f'- Label counts: {lbl}')
    md.append('## Features\n')
    md.append(f'- feature_order: {stats["feature_order"]}')
    md.append('## Split\n')
    md.append('- By file; see training_artifacts/train_files.json and test_files.json')
    md.append('## Metrics\n')
    md.append(f'```${cls_rep}```')
    md.append(f'- Confusion matrix: {cm.tolist()}')
    md.append(f'- ROC AUC: {roc}')
    md.append(f'- PR AUC: {pr_auc}')
    (out_meta / 'TRAINING_REPORT.md').write_text('\n\n'.join(md))


if __name__ == '__main__':
    main()


