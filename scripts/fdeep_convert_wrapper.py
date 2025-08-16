#!/usr/bin/env python3
"""
Wrapper around frugally-deep's convert_model.py that ensures compatibility with
current Keras versions, without modifying the immutable frugally-deep source.

Usage:
  python scripts/fdeep_convert_wrapper.py <input_keras_path> <output_fdeep_json> [--no-tests]
"""
import sys
import os
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: fdeep_convert_wrapper.py <input.keras> <output.json> [--no-tests]")
        return 2

    in_path = sys.argv[1]
    out_path = sys.argv[2]
    no_tests = ('--no-tests' in sys.argv[3:])

    import importlib
    # Pre-patch image_preprocessing package BEFORE importing keras.layers aggregator
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
        class _DummyLayer:
            def __init__(self, *args, **kwargs):
                pass
        for name in ['RandomHeight', 'RandomWidth']:
            if not hasattr(img_prep, name):
                try:
                    setattr(img_prep, name, _DummyLayer)
                except Exception:
                    pass
    except Exception:
        pass

    import keras  # type: ignore
    # Keras 3: ensure top-level Layer exists
    try:
        if not hasattr(keras, 'Layer'):
            layers_mod = importlib.import_module('keras.layers')
            setattr(keras, 'Layer', getattr(layers_mod, 'Layer'))
    except Exception:
        pass
    # Some frugally-deep converter versions expect keras.src.utils.tf_utils.is_tensor_or_tensor_list
    try:
        tf_utils = importlib.import_module('keras.src.utils.tf_utils')
        if not hasattr(tf_utils, 'is_tensor_or_tensor_list'):
            # Patch in a compatible helper
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
                    res = True
                    for t in x:
                        try:
                            if _is_tensor is not None and not _is_tensor(t):
                                res = False
                                break
                        except Exception:
                            res = False
                            break
                    return res
                return False
            setattr(tf_utils, 'is_tensor_or_tensor_list', _is_tensor_or_tensor_list)
    except Exception:
        pass
    # Provide CenterCrop in keras.src.layers.preprocessing.image_preprocessing if missing
    # Already pre-patched above; keep block for safety if Keras re-imports package
    try:
        img_prep = importlib.import_module('keras.src.layers.preprocessing.image_preprocessing')
        # Ensure Rescaling export in image_preprocessing package
        try:
            from keras.src.layers.preprocessing.image_preprocessing import Rescaling as _ImgRescaling  # type: ignore
        except Exception:
            _ImgRescaling = None
        if _ImgRescaling is None:
            try:
                from keras.src.layers.preprocessing.rescaling import Rescaling as _Rescaling  # type: ignore
                setattr(img_prep, 'Rescaling', _Rescaling)
            except Exception:
                pass
        if not hasattr(img_prep, 'CenterCrop'):
            try:
                from keras.src.layers.preprocessing.image_preprocessing.center_crop import CenterCrop as _CenterCrop  # type: ignore
                setattr(img_prep, 'CenterCrop', _CenterCrop)
            except Exception:
                pass
        for name in ['RandomHeight', 'RandomWidth']:
            if not hasattr(img_prep, name):
                class _DummyLayer:
                    def __init__(self, *args, **kwargs):
                        pass
                try:
                    setattr(img_prep, name, _DummyLayer)
                except Exception:
                    pass
    except Exception:
        pass

    # Patch normalization SyncBatchNormalization symbol if missing
    try:
        bn_mod = importlib.import_module('keras.src.layers.normalization.batch_normalization')
        if not hasattr(bn_mod, 'SyncBatchNormalization'):
            # Fallback: alias to BatchNormalization to satisfy imports; converter won't use it
            if hasattr(bn_mod, 'BatchNormalization'):
                setattr(bn_mod, 'SyncBatchNormalization', getattr(bn_mod, 'BatchNormalization'))
            else:
                class _DummyBN:
                    def __init__(self, *args, **kwargs):
                        pass
                setattr(bn_mod, 'SyncBatchNormalization', _DummyBN)
    except Exception:
        pass

    # Import converter module from frugally-deep without modifying it
    repo_root = Path(__file__).resolve().parents[1]
    converter_path = repo_root.parent / 'frugally-deep' / 'keras_export'
    sys.path.insert(0, str(converter_path))
    try:
        import convert_model  # type: ignore
    except Exception as e:
        print(f"ERROR: Failed to import frugally-deep converter: {e}")
        return 1

    try:
        convert_model.convert(in_path, out_path, no_tests)
    except Exception as e:
        print(f"ERROR: Conversion failed: {e}")
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


