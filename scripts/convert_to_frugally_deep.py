#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path


def _patch_keras_for_converter() -> None:
	# Patch Keras internals expected by frugally-deep converter without touching its code
	import importlib
	import keras  # type: ignore

	# Ensure tf_utils.is_tensor_or_tensor_list exists
	try:
		tf_utils = importlib.import_module('keras.src.utils.tf_utils')
		if not hasattr(tf_utils, 'is_tensor_or_tensor_list'):
			try:
				from keras.src.backend import is_tensor as _is_tensor  # type: ignore
			except Exception:
				_is_tensor = None

			def _is_tensor_or_tensor_list(x):  # type: ignore
				try:
					if _is_tensor is not None and _is_tensor(x):
						return True
				except Exception:
					pass
				if isinstance(x, (list, tuple)):
					for t in x:
						try:
							if _is_tensor is None or not _is_tensor(t):
								return False
						except Exception:
							return False
					return True
				return False

			setattr(tf_utils, 'is_tensor_or_tensor_list', _is_tensor_or_tensor_list)
	except Exception:
		pass

	# Re-export image preprocessing symbols commonly imported by converter
	try:
		img_prep = importlib.import_module('keras.src.layers.preprocessing.image_preprocessing')
		pkg_path = Path(img_prep.__file__).parent
		for py in pkg_path.glob('*.py'):
			if py.name == '__init__.py':
				continue
			mod_name = f"keras.src.layers.preprocessing.image_preprocessing.{py.stem}"
			try:
				subm = importlib.import_module(mod_name)
			except Exception:
				continue
			for attr in dir(subm):
				if attr.startswith('_'):
					continue
				try:
					val = getattr(subm, attr)
				except Exception:
					continue
				if not hasattr(img_prep, attr):
					try:
						setattr(img_prep, attr, val)
					except Exception:
						pass
		# Ensure Rescaling in package
		if not hasattr(img_prep, 'Rescaling'):
			try:
				from keras.src.layers.preprocessing.rescaling import Rescaling as _Rescaling  # type: ignore
				setattr(img_prep, 'Rescaling', _Rescaling)
			except Exception:
				pass
		# Provide placeholders for rare imports
		class _DummyLayer:
			def __init__(self, *args, **kwargs):
				pass
		for name in ['RandomHeight', 'RandomWidth']:
			if not hasattr(img_prep, name):
				setattr(img_prep, name, _DummyLayer)
	except Exception:
		pass

	# Normalization: alias SyncBatchNormalization to BatchNormalization if missing
	try:
		bn_mod = importlib.import_module('keras.src.layers.normalization.batch_normalization')
		if not hasattr(bn_mod, 'SyncBatchNormalization') and hasattr(bn_mod, 'BatchNormalization'):
			setattr(bn_mod, 'SyncBatchNormalization', getattr(bn_mod, 'BatchNormalization'))
		# Also provide BatchNormalizationBase if converter expects it
		if not hasattr(bn_mod, 'BatchNormalizationBase') and hasattr(bn_mod, 'BatchNormalization'):
			setattr(bn_mod, 'BatchNormalizationBase', getattr(bn_mod, 'BatchNormalization'))
	except Exception:
		pass

	# Ensure keras.Layer at top-level
	try:
		if not hasattr(keras, 'Layer'):
			layers_mod = importlib.import_module('keras.layers')
			setattr(keras, 'Layer', getattr(layers_mod, 'Layer'))
	except Exception:
		pass


def main() -> None:
	parser = argparse.ArgumentParser(description='Convert Keras model to frugally-deep JSON')
	parser.add_argument('input_path', type=str)
	parser.add_argument('output_path', type=str)
	parser.add_argument('--no-tests', action='store_true')
	args = parser.parse_args()

	# Use the current Python environment as-is to ensure keras/tf are importable
	# (No env stripping; rely on caller to choose the right interpreter)

	_patch_keras_for_converter()

	# Import and call converter directly in-process so our patches are in effect
	repo_root = Path(__file__).resolve().parents[1]
	sys.path.insert(0, str((repo_root.parent / 'frugally-deep' / 'keras_export')))
	# Ensure tf_utils has shape_type_conversion decorator if missing
	try:
		import importlib as _il
		tf_utils = _il.import_module('keras.src.utils.tf_utils')
		if not hasattr(tf_utils, 'shape_type_conversion'):
			def _shape_type_conversion(fn):
				return fn
			setattr(tf_utils, 'shape_type_conversion', _shape_type_conversion)
	except Exception:
		pass
	import convert_model  # type: ignore
	convert_model.convert(args.input_path, args.output_path, args.no_tests)


if __name__ == '__main__':
    main() 