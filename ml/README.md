# CyberGuard ML pipeline (phishing URL model)

Owner: Zoya Khalid. Jira: SCRUM-10 (epic), SCRUM-21 (dataset), SCRUM-22 (training / ONNX).

The phishing scanner scores a URL in two ways and combines them:

1. **Heuristic rules** in C# (`UrlRiskEngine`), already in the repo.
2. **ML model** trained here, exported to ONNX, and loaded by the API through the
   `IPhishingModel` interface (SCRUM-26, Maha).

The model never sees the page content. It only sees numbers computed from the URL string
(see `features.py`), so the server never has to visit a possibly dangerous site.

## Folder layout

```
ml/
  README.md            this file
  requirements.txt     python packages
  features.py          URL -> 15 numeric features (mirrors C# UrlFeatureExtractor)
  test_features.py     tests for features.py
  prepare_dataset.py   clean the PhiUSIIL csv, build features, train/test split
  train_lightgbm.py    Optuna tuning + LightGBM training + ONNX export + metrics
  data/                (git-ignored) raw and prepared data
  artifacts/           (git-ignored *.onnx) model, metrics.json
```

## Setup

```bash
cd ml
python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell
pip install -r requirements.txt
python -m pytest -q             # features tests must pass
```

## Dataset

Download the **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository) and put
the csv at `ml/data/PhiUSIIL_Phishing_URL_Dataset.csv`. It has a `URL` column and a
`label` column. Check the dataset page for what `label` means: as far as we know,
`1` = legitimate and `0` = phishing. `prepare_dataset.py` has a `--phishing-label-value`
option so you can flip it if the dataset page says otherwise.

## Pipeline

```bash
python prepare_dataset.py --input data/PhiUSIIL_Phishing_URL_Dataset.csv --output-dir data/prepared
python train_lightgbm.py --data-dir data/prepared --output-dir artifacts --trials 25
```

The training script writes `artifacts/phishing_model.onnx` and `artifacts/metrics.json`.
The `.onnx` file is git-ignored (see `.gitignore`); share it with the team by another
route (Google Drive) or attach it to a GitHub release.

## Rule of the pipeline

`features.py` and `UrlFeatureExtractor.cs` must always produce the same numbers for the
same URL. If you change one, change the other and update both tests.
