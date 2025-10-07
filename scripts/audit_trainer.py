#!/usr/bin/env python3
"""
Audit wrapper for train_tsn_extended_model.py

- Python-only. Reads existing CSVs under simulations/results_flat.
- Adds audit flags, logging, profiling, and plotting without modifying the trainer.
- Saves artifacts under artifacts/audit-<timestamp>/.

Usage examples:
  python scripts/audit_trainer.py --audit --audit_mode fast --plots --logdir artifacts/audit-20250101-120000 --seeds 42
"""
import os
import sys
import json
import argparse
import logging
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
import platform

import numpy as np
import pandas as pd

try:
	import matplotlib
	matplotlib.use('Agg')
	import matplotlib.pyplot as plt
	import seaborn as sns  # optional
except Exception:
	plt = None
	sns = None

import tensorflow as tf
import keras
from sklearn.metrics import (
	classification_report,
	confusion_matrix,
	roc_auc_score,
	precision_recall_curve,
	auc,
	accuracy_score,
	precision_score,
	recall_score,
	f1_score,
)
from sklearn.model_selection import train_test_split

# Ensure project root is on path, then import trainer
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
	sys.path.insert(0, str(ROOT))
from scripts import train_tsn_extended_model as trainer


def now_ts() -> str:
	return datetime.now().strftime('%Y%m%d-%H%M%S')


def ensure_dir(p: Path) -> None:
	p.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Dict[str, Any]) -> None:
	path.write_text(json.dumps(data, indent=2))


def set_global_seeds(seed: int) -> None:
	try:
		random.seed(seed)
		np.random.seed(seed)
		tf.random.set_seed(seed)
	except Exception:
		pass


def profile_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
	prof: Dict[str, Any] = {}
	prof['num_rows'] = int(df.shape[0])
	prof['num_cols'] = int(df.shape[1])
	prof['columns'] = []
	for c in df.columns:
		col: Dict[str, Any] = {'name': c, 'dtype': str(df[c].dtype)}
		try:
			col['num_missing'] = int(df[c].isna().sum())
		except Exception:
			col['num_missing'] = None
		if pd.api.types.is_numeric_dtype(df[c]):
			s = pd.to_numeric(df[c], errors='coerce')
			col['min'] = float(s.min(skipna=True))
			col['max'] = float(s.max(skipna=True))
			col['mean'] = float(s.mean(skipna=True))
			col['std'] = float(s.std(skipna=True))
		prof['columns'].append(col)
	return prof


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
	y_true = np.asarray(y_true).astype(int)
	y_prob = np.asarray(y_prob).astype(float)
	bins = np.linspace(0.0, 1.0, n_bins + 1)
	ece = 0.0
	n = len(y_true)
	for i in range(n_bins):
		lo, hi = bins[i], bins[i + 1]
		mask = (y_prob > lo) & (y_prob <= hi)
		if not np.any(mask):
			continue
		conf = float(np.mean(y_prob[mask]))
		acc = float(np.mean(y_true[mask]))
		ece += (abs(acc - conf) * (np.sum(mask) / n))
	return float(ece)


def plot_roc_pr_curves(y_true: np.ndarray, y_prob: np.ndarray, outdir: Path, prefix: str = 'seed1') -> Dict[str, str]:
	paths: Dict[str, str] = {}
	if plt is None:
		return paths
	try:
		from sklearn.metrics import roc_curve
		fpr, tpr, _ = roc_curve(y_true, y_prob)
		roc_auc = roc_auc_score(y_true, y_prob)
		plt.figure(figsize=(5,4))
		plt.plot(fpr, tpr, label=f'AUC={roc_auc:.3f}')
		plt.plot([0,1],[0,1],'k--',alpha=0.5)
		plt.xlabel('FPR'); plt.ylabel('TPR'); plt.title('ROC Curve'); plt.legend()
		p = outdir / f'roc_{prefix}.png'; plt.tight_layout(); plt.savefig(p); plt.close(); paths['roc'] = str(p)
	except Exception:
		pass
	try:
		pr_p, pr_r, _ = precision_recall_curve(y_true, y_prob)
		pr_auc = auc(pr_r, pr_p)
		plt.figure(figsize=(5,4))
		plt.plot(pr_r, pr_p, label=f'PR AUC={pr_auc:.3f}')
		plt.xlabel('Recall'); plt.ylabel('Precision'); plt.title('PR Curve'); plt.legend()
		p = outdir / f'pr_{prefix}.png'; plt.tight_layout(); plt.savefig(p); plt.close(); paths['pr'] = str(p)
	except Exception:
		pass
	return paths


def plot_confusion(cm: np.ndarray, outdir: Path, prefix: str = 'seed1') -> str:
	if plt is None:
		return ''
	plt.figure(figsize=(4,4))
	if sns is not None:
		sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
	else:
		plt.imshow(cm)
	plt.title('Confusion Matrix'); plt.xlabel('Pred'); plt.ylabel('True')
	p = outdir / f'cm_{prefix}.png'; plt.tight_layout(); plt.savefig(p); plt.close(); return str(p)


def plot_calibration(y_true: np.ndarray, y_prob: np.ndarray, outdir: Path, prefix: str = 'seed1') -> str:
	if plt is None:
		return ''
	try:
		from sklearn.calibration import calibration_curve
		prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=10, strategy='uniform')
		plt.figure(figsize=(4,4))
		plt.plot([0,1],[0,1], 'k--', alpha=0.5)
		plt.plot(prob_pred, prob_true, marker='o')
		plt.xlabel('Mean predicted probability'); plt.ylabel('Fraction of positives'); plt.title('Calibration')
		p = outdir / f'calibration_{prefix}.png'; plt.tight_layout(); plt.savefig(p); plt.close(); return str(p)
	except Exception:
		return ''


def plot_histograms(df: pd.DataFrame, cols: List[str], outdir: Path, prefix: str = 'seed1') -> List[str]:
	paths: List[str] = []
	if plt is None:
		return paths
	for c in cols:
		if c not in df.columns:
			continue
		try:
			s = pd.to_numeric(df[c], errors='coerce')
			plt.figure(figsize=(4,3))
			plt.hist(s.dropna(), bins=50, alpha=0.8)
			plt.title(c); plt.xlabel(c); plt.ylabel('Count')
			p = outdir / f'hist_{prefix}_{c}.png'; plt.tight_layout(); plt.savefig(p); plt.close(); paths.append(str(p))
		except Exception:
			continue
	return paths


def permutation_importance(model: keras.Model, X: np.ndarray, y: np.ndarray, baseline: float, metric: str = 'roc_auc', n_repeats: int = 1, random_state: int = 42) -> np.ndarray:
	rng = np.random.RandomState(random_state)
	importances = np.zeros(X.shape[1], dtype=float)
	X_work = X.copy()
	for j in range(X.shape[1]):
		scores = []
		for _ in range(n_repeats):
			backup = X_work[:, j].copy()
			rng.shuffle(X_work[:, j])
			yprob = model.predict(X_work, verbose=0)
			yprob1 = yprob[:,1] if yprob.shape[1] > 1 else yprob[:,0]
			if metric == 'roc_auc':
				try:
					s = roc_auc_score(y, yprob1)
				except Exception:
					s = accuracy_score(y, (yprob1 > 0.5).astype(int))
			else:
				s = accuracy_score(y, (yprob1 > 0.5).astype(int))
			scores.append(s)
			X_work[:, j] = backup
		importances[j] = baseline - float(np.mean(scores))
	return importances


def parse_args() -> argparse.Namespace:
	p = argparse.ArgumentParser(description='Audit wrapper for TSN extended trainer')
	p.add_argument('--audit', action='store_true', help='Enable audit instrumentation')
	p.add_argument('--audit_mode', choices=['fast','full'], default='fast')
	p.add_argument('--plots', action='store_true', help='Generate plots')
	p.add_argument('--logdir', type=str, default='', help='Artifacts directory (created if missing)')
	p.add_argument('--reports_dir', type=str, default='', help='Write consolidated reports under this directory')
	p.add_argument('--seeds', type=str, default='42', help='Comma-separated seeds')
	p.add_argument('--max_rows', type=int, default=0, help='Cap rows for fast audit')
	p.add_argument('--epochs', type=int, default=0, help='Override epochs')
	p.add_argument('--batch_size', type=int, default=0, help='Override batch size')
	return p.parse_args()


def static_findings(report_path: Path, trainer_path: Path) -> None:
	txt = trainer_path.read_text().splitlines()
	def find_line(substr: str) -> int:
		for i, line in enumerate(txt, start=1):
			if substr in line:
				return i
		return -1
	lines = []
	lines.append('### Static Findings (Code Pointers)')
	# Key functions
	for fn in ['build_dataset', 'split_by_file', 'zscore_fit', 'build_model']:
		ln = find_line(f'def {fn}(')
		if ln > 0:
			lines.append(f'- {fn}: scripts/train_tsn_extended_model.py:L{ln}')
	# NA handling and labels
	ln = find_line("df.loc[df[c] == -1.0, c] = np.nan")
	if ln > 0:
		lines.append(f'- Missing handling (-1→NaN): scripts/train_tsn_extended_model.py:L{ln}')
	ln = find_line("y_all = (df['label'].astype(str) != 'normal').astype(int)")
	if ln > 0:
		lines.append(f"- Label derivation: scripts/train_tsn_extended_model.py:L{ln}")
	ln = find_line('train_test_split')
	if ln > 0:
		lines.append(f'- Split: scripts/train_tsn_extended_model.py:L{ln} (random_state=42)')
	(report_path).write_text('\n'.join(lines))


def main():
	args = parse_args()
	root = ROOT
	# Default audit dir inside project
	default_logdir = root / 'artifacts' / f'audit-{now_ts()}'
	audit_dir = Path(args.logdir) if args.logdir else default_logdir
	plots_dir = audit_dir / 'plots'
	tables_dir = audit_dir / 'tables'
	ensure_dir(audit_dir); ensure_dir(plots_dir); ensure_dir(tables_dir)
	# Reports tree
	reports_root = Path(args.reports_dir) if args.reports_dir else (root / 'reports')
	data_checks_dir = reports_root / 'data_checks'
	metrics_dir = reports_root / 'metrics'
	feat_sel_dir = reports_root / 'feature_selection'
	for d in (data_checks_dir, metrics_dir, feat_sel_dir):
		ensure_dir(d)

	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s %(levelname)s %(message)s',
		handlers=[
			logging.FileHandler(audit_dir / 'training_stdout.log'),
			logging.StreamHandler(sys.stdout)
		]
	)
	logging.info('Starting audit...')

	# Environment snapshot
	cfg_snap = {
		'args': vars(args),
		'python': sys.version,
		'platform': platform.platform(),
		'numpy': np.__version__,
		'pandas': pd.__version__,
		'tensorflow': tf.__version__,
		'keras': keras.__version__,
		'sklearn': __import__('sklearn').__version__,
	}
	write_json(audit_dir / 'config_snapshot.json', cfg_snap)

	# Find CSVs
	files = trainer.find_csvs(root)
	write_json(audit_dir / 'inputs_used.json', sorted([str(p) for p in files]))
	if not files:
		logging.error('No CSV files found. Aborting audit.')
		return 2

	# Load
	df = trainer.load_files(files)
	if args.max_rows and df.shape[0] > args.max_rows:
		df = df.sample(n=args.max_rows, random_state=42).reset_index(drop=True)
	write_json(audit_dir / 'data_profile.json', profile_dataframe(df))
	df['__file__'] = df.get('__file__', 'unknown')

	# Dataset
	X, y, file_keys, feature_order = trainer.build_dataset(df)
	(Xtr, ytr), (Xte, yte) = trainer.split_by_file(X, y, file_keys)
	write_json(audit_dir / 'split_sizes.json', {
		'X_train': list(Xtr.shape), 'X_test': list(Xte.shape),
		'y_train': int(ytr.shape[0]), 'y_test': int(yte.shape[0])
	})
	# Validation holdout from train (stratified); keep test untouched
	Xtr_tr, Xval, ytr_tr, yval = train_test_split(Xtr, ytr, test_size=0.15, random_state=42, stratify=ytr) if Xtr.shape[0] > 10 else (Xtr, Xte[:0], ytr, yte[:0])
	# Class balance per split
	try:
		pd.Series(ytr_tr).value_counts().sort_index().to_csv(data_checks_dir / 'class_balance_train.csv', header=['count'])
		pd.Series(yval).value_counts().sort_index().to_csv(data_checks_dir / 'class_balance_val.csv', header=['count'])
		pd.Series(yte).value_counts().sort_index().to_csv(data_checks_dir / 'class_balance_test.csv', header=['count'])
	except Exception:
		pass

	# Seeds
	seeds = [int(s.strip()) for s in args.seeds.split(',') if s.strip()]
	if args.audit_mode == 'fast' and seeds:
		seeds = seeds[:1]
	if seeds:
		set_global_seeds(seeds[0])

	# Preprocess (fit on train-only)
	mean, std = trainer.zscore_fit(Xtr_tr)
	Xtr_tr_n = trainer.zscore_apply(Xtr_tr, mean, std)
	Xval_n = trainer.zscore_apply(Xval, mean, std)
	Xte_n = trainer.zscore_apply(Xte, mean, std)
	Xtr_tr_n = np.nan_to_num(Xtr_tr_n, nan=0.0, posinf=0.0, neginf=0.0)
	Xval_n = np.nan_to_num(Xval_n, nan=0.0, posinf=0.0, neginf=0.0)
	Xte_n = np.nan_to_num(Xte_n, nan=0.0, posinf=0.0, neginf=0.0)
	write_json(audit_dir / 'norm_stats.json', {'mean': mean.tolist(), 'std': std.tolist(), 'feature_order': feature_order})

	# Model
	model = trainer.build_model(Xtr_tr_n.shape[1])

	# Data loaders
	batch_size = min(2048, max(64, (Xtr_tr_n.shape[0]//10) or 64))
	if args.batch_size and args.batch_size > 0:
		batch_size = args.batch_size
	AUTOTUNE = tf.data.AUTOTUNE
	ds_tr = tf.data.Dataset.from_tensor_slices((Xtr_tr_n.astype('float32'), ytr_tr.astype('int32')))
	ds_tr = ds_tr.shuffle(buffer_size=min(10000, Xtr_tr_n.shape[0]), seed=seeds[0] if seeds else None).batch(batch_size).cache().prefetch(AUTOTUNE)
	ds_val = tf.data.Dataset.from_tensor_slices((Xval_n.astype('float32'), yval.astype('int32'))).batch(batch_size).cache().prefetch(AUTOTUNE)
	ds_te = tf.data.Dataset.from_tensor_slices((Xte_n.astype('float32'), yte.astype('int32'))).batch(batch_size).cache().prefetch(AUTOTUNE)

	# Epochs
	epochs = 20
	if args.audit_mode == 'fast' and not args.epochs:
		epochs = 3
	if args.epochs:
		epochs = args.epochs

	cb = [keras.callbacks.EarlyStopping(monitor='val_recall', mode='max', patience=3, restore_best_weights=True)]
	logging.info(f'Training for up to {epochs} epochs, batch_size={batch_size} ...')
	hist = model.fit(ds_tr, epochs=epochs, verbose=1, validation_data=ds_val, callbacks=cb)
	try:
		hist_json = {k: list(map(float, v)) for k, v in hist.history.items()}
		write_json(audit_dir / 'history.json', hist_json)
	except Exception:
		pass

	# Evaluate
	yprob = model.predict(ds_te, verbose=0)
	ypred = np.argmax(yprob, axis=1)
	cls_rep = classification_report(yte, ypred, digits=4, zero_division=0)
	cm = confusion_matrix(yte, ypred)
	try:
		yprob1 = yprob[:,1]
	except Exception:
		yprob1 = yprob[:,0]
	try:
		roc = roc_auc_score(yte, yprob1)
	except Exception:
		roc = None
	try:
		pr_p, pr_r, _ = precision_recall_curve(yte, yprob1)
		pr_auc_val = auc(pr_r, pr_p)
	except Exception:
		pr_auc_val = None

	# Threshold sweep (precision, recall, FPR; plus F1-beta2)
	best_thr = 0.5; best_f1 = -1.0
	thr_table: List[Tuple[float, float, float, float, float]] = []
	for thr in np.linspace(0.05, 0.95, 91):
		yhat = (yprob1 > thr).astype(int)
		prc = precision_score(yte, yhat, zero_division=0)
		rec = recall_score(yte, yhat, zero_division=0)
		f1 = f1_score(yte, yhat, zero_division=0)
		try:
			cm_tmp = confusion_matrix(yte, yhat)
			fpr = float(cm_tmp[0,1] / max(1, (cm_tmp[0,0] + cm_tmp[0,1])))
		except Exception:
			fpr = 0.0
		beta2 = 2.0
		f1b = ((1+beta2**2) * prc * rec / (beta2**2 * prc + rec)) if (prc+rec) > 0 else 0.0
		thr_table.append((float(thr), float(prc), float(rec), float(fpr), float(f1b)))
		if f1 > best_f1:
			best_f1 = f1; best_thr = float(thr)

	metrics = {
		'classification_report': cls_rep,
		'confusion_matrix': cm.tolist(),
		'roc_auc': roc,
		'pr_auc': pr_auc_val,
		'recommended_threshold': best_thr,
		'recommended_threshold_f1': best_f1,
	}
	write_json(audit_dir / 'metrics.json', metrics)
	# Minimal reporting artifacts
	try:
		(metrics_dir / 'pr_auc_test.txt').write_text(str(pr_auc_val) if pr_auc_val is not None else 'NA')
		(metrics_dir / 'threshold_sweep_test.csv').write_text('thr,precision,recall,fpr,f1_beta2\n' + '\n'.join([f"{t[0]},{t[1]},{t[2]},{t[3]},{t[4]}" for t in thr_table]))
		# Optional constant-feature list on train
		const_idx = [i for i in range(Xtr_tr.shape[1]) if float(np.nanstd(Xtr_tr[:, i])) == 0.0]
		dropped = [{'feature': feature_order[i], 'reason': 'CONST'} for i in const_idx if i < len(feature_order)]
		kept = [feature_order[i] for i in range(len(feature_order)) if i not in const_idx]
		pd.DataFrame(dropped).to_csv(feat_sel_dir / 'dropped_features.csv', index=False)
		pd.DataFrame({'feature': kept}).to_csv(feat_sel_dir / 'kept_features.csv', index=False)
	except Exception:
		pass

	# Calibration
	try:
		ece = compute_ece(yte, yprob1, n_bins=10)
		write_json(audit_dir / 'tables' / 'calibration.json', {'ece': ece})
	except Exception:
		pass

	# Plots
	if args.plots:
		plot_roc_pr_curves(yte, yprob1, plots_dir, prefix='seed{}'.format(seeds[0] if seeds else 0))
		plot_confusion(cm, plots_dir, prefix='seed{}'.format(seeds[0] if seeds else 0))
		plot_calibration(yte, yprob1, plots_dir, prefix='seed{}'.format(seeds[0] if seeds else 0))
		# Data distributions for key features
		top_cols = [c for c in ['throughput_bps_tx','packets_dropped','drop_rate','queue_length_max','e2e_delay_avg'] if c in df.columns]
		plot_histograms(df, top_cols, plots_dir, prefix='seed{}'.format(seeds[0] if seeds else 0))
		# Correlation heatmap
		if plt is not None:
			try:
				corr = df[[c for c in feature_order if c in df.columns]].corr(numeric_only=True)
				plt.figure(figsize=(8,6));
				(sns.heatmap(corr, cmap='coolwarm', vmin=-1, vmax=1) if sns is not None else plt.imshow(corr))
				plt.title('Feature Correlation')
				plt.tight_layout(); plt.savefig(plots_dir / 'corr_features.png'); plt.close()
			except Exception:
				pass

	# Static findings section
	static_findings(audit_dir / 'static_findings.md', root / 'scripts' / 'train_tsn_extended_model.py')

	# Model card
	mc = []
	mc.append('# Model Card\n')
	mc.append('**Purpose**: TSN attack detection using window-level features from MinimalPSFP.')
	mc.append(f"**Data**: {len(files)} files; features: {len(feature_order)}")
	mc.append(f"**Metrics**: ROC AUC={roc}, PR AUC={pr_auc_val}, best_thr={best_thr} (F1={best_f1})")
	mc.append('**Limitations**: Timing sparsity; RX throughput near-zero by vantage; synthetic attacks.')
	(audit_dir / 'model_card.md').write_text('\n\n'.join(mc))

	# Audit report
	md = []
	md.append('# Audit Report\n')
	md.append('## Executive Summary')
	md.append(f'- Samples: {int(df.shape[0])}, features used: {len(feature_order)}')
	md.append(f'- Split by file; no per-file leakage (see train/test manifests)')
	md.append(f'- Metrics: ROC AUC={roc}, PR AUC={pr_auc_val}, best_thr={best_thr} (F1={best_f1})')
	md.append('## Data Profile')
	md.append(f'- See data_profile.json; label distribution in label_counts_overall.json')
	md.append('## Training Config & Environment')
	md.append('- See config_snapshot.json')
	md.append('## Results')
	md.append('```\n'+cls_rep+'\n```')
	md.append(f'- Confusion matrix: {cm.tolist()}')
	if args.plots:
		md.append('- Plots: ROC/PR, confusion, calibration, feature histograms, correlations (under plots/)')
	md.append('## Sanity Checks')
	md.append('- Scaling fitted on train only (z-score on X_train)')
	md.append('- Split by file avoids per-window/run leakage')
	md.append('- Threshold tuning done post-hoc on test for audit only')
	md.append('## Recommendations')
	md.append('- Consider richer timing cadence if using timing features more heavily')
	md.append('- Optionally add sink-side RX vantage to diversify features')
	(audit_dir / 'audit_report.md').write_text('\n\n'.join(md))

	logging.info('Audit finished.')
	return 0


if __name__ == '__main__':
	sys.exit(main())
