# ML evaluation report (template)

Owner: Zoya Khalid. Jira: SCRUM-10 / SCRUM-22. Fill this in after you run the pipeline on
the real PhiUSIIL dataset. Do not invent numbers: copy them from `artifacts/metrics.json`.

## 1. Goal

Predict whether a URL is phishing from numeric features of the URL string alone, so the
server never visits the site.

## 2. Data

| Item | Value |
|---|---|
| Dataset | PhiUSIIL Phishing URL Dataset (UCI) |
| Rows before cleaning | |
| Rows after cleaning (nulls, empty, duplicate URLs removed) | |
| Phishing share | |
| Train / test split | 80 / 20, stratified, seed 42 |

## 3. Features

The 15 features in `ml/features.py` (same as `UrlFeatureExtractor.cs`). Add a short note
on which ones you expect to matter most and why.

## 4. Method

- Model: LightGBM classifier.
- Tuning: Optuna, number of trials: ___, objective: 3-fold cross-validated ROC-AUC.
- Best parameters: (copy from metrics.json)
- Calibration: (method used, Brier score before and after)

## 5. Results on the held-out test set

| Metric | Value |
|---|---|
| ROC-AUC | |
| Accuracy | |
| Precision | |
| Recall | |
| F1 | |

Add the confusion matrix and one sentence on what the false positives and false
negatives look like (legitimate sites flagged versus phishing sites missed).

## 6. ONNX export check

Maximum difference between ONNX and LightGBM probabilities on 200 test rows: ___
(should be close to 0).

## 7. Limitations

- Dataset age and source bias.
- URL-only features cannot see page content.
- Possible gap between this dataset and URLs our users paste.

## 8. Next steps

Hand the `.onnx` file to Maha for `OnnxPhishingModel` (SCRUM-26).
