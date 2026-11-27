"""Train the phishing model with LightGBM + Optuna and export it to ONNX (SCRUM-22).

Example:
    python train_lightgbm.py --data-dir data/prepared --output-dir artifacts --trials 25

Outputs in --output-dir:
    phishing_model.onnx   the model the C# API loads (input: float tensor [N, 15])
    metrics.json          test-set metrics + best hyper-parameters

TODO (your part of SCRUM-22): calibrate the probabilities. LightGBM scores are often
over- or under-confident. Fit a calibrator (Platt scaling or isotonic regression) on a
validation split, report the Brier score before and after, and decide where the
calibration is applied (in Python before export, or in C# after the ONNX output).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import optuna
import pandas as pd
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score

from features import FEATURE_NAMES

TARGET = "is_phishing"


def load(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    return pd.read_csv(data_dir / "train.csv"), pd.read_csv(data_dir / "test.csv")


def tune(x: pd.DataFrame, y: pd.Series, trials: int, seed: int) -> dict:
    """Search hyper-parameters with Optuna, maximising cross-validated ROC-AUC."""

    def objective(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 600),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "num_leaves": trial.suggest_int("num_leaves", 15, 127),
            "min_child_samples": trial.suggest_int("min_child_samples", 10, 100),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        }
        model = lgb.LGBMClassifier(**params, subsample_freq=1, random_state=seed, verbose=-1)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=seed)
        return cross_val_score(model, x, y, cv=cv, scoring="roc_auc").mean()

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=trials)
    print(f"best cv roc_auc: {study.best_value:.4f}")
    return study.best_params


def evaluate(model: lgb.LGBMClassifier, x: pd.DataFrame, y: pd.Series) -> dict:
    proba = model.predict_proba(x)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "roc_auc": float(roc_auc_score(y, proba)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred)),
        "recall": float(recall_score(y, pred)),
        "f1": float(f1_score(y, pred)),
    }


def export_onnx(model: lgb.LGBMClassifier, path: Path) -> None:
    initial_types = [("features", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = convert_lightgbm(model, initial_types=initial_types, target_opset=15)
    path.write_bytes(onnx_model.SerializeToString())


def check_onnx_matches_python(model: lgb.LGBMClassifier, onnx_path: Path, x: pd.DataFrame) -> float:
    """Load the exported file and compare its probabilities with LightGBM's own."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    sample = x.head(200).to_numpy(dtype=np.float32)
    outputs = session.run(None, {"features": sample})
    # outputs[1] holds per-class probabilities (list of dicts or an array, depending on version)
    probs = outputs[1]
    onnx_p = np.array([row[1] for row in probs]) if isinstance(probs, list) else np.asarray(probs)[:, 1]
    py_p = model.predict_proba(x.head(200))[:, 1]
    return float(np.max(np.abs(onnx_p - py_p)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--trials", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_df, test_df = load(args.data_dir)
    x_train, y_train = train_df[FEATURE_NAMES], train_df[TARGET]
    x_test, y_test = test_df[FEATURE_NAMES], test_df[TARGET]

    best_params = tune(x_train, y_train, args.trials, args.seed)

    model = lgb.LGBMClassifier(**best_params, subsample_freq=1, random_state=args.seed, verbose=-1)
    model.fit(x_train, y_train)

    metrics = evaluate(model, x_test, y_test)
    print("test metrics:", json.dumps(metrics, indent=2))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = args.output_dir / "phishing_model.onnx"
    export_onnx(model, onnx_path)

    max_diff = check_onnx_matches_python(model, onnx_path, x_test)
    print(f"max |onnx - lightgbm| probability difference: {max_diff:.6f}")

    report = {
        "features": FEATURE_NAMES,
        "best_params": best_params,
        "test_metrics": metrics,
        "onnx_max_abs_diff": max_diff,
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
    }
    (args.output_dir / "metrics.json").write_text(json.dumps(report, indent=2))
    print(f"saved {onnx_path} and metrics.json")


if __name__ == "__main__":
    main()
