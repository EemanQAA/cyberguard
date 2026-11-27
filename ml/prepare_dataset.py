"""Prepare the PhiUSIIL dataset for training (SCRUM-21).

Reads the raw csv, cleans it, turns every URL into the 15 numeric features from
features.py, splits into train/test sets and writes them as csv files.

Example:
    python prepare_dataset.py --input data/PhiUSIIL_Phishing_URL_Dataset.csv --output-dir data/prepared
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, extract_features


def load_and_clean(path: Path, url_col: str, label_col: str, phishing_label_value: int) -> pd.DataFrame:
    df = pd.read_csv(path)

    missing = [c for c in (url_col, label_col) if c not in df.columns]
    if missing:
        raise SystemExit(f"Column(s) {missing} not found. Columns in file: {list(df.columns)[:15]} ...")

    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label"})
    before = len(df)

    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df = df.drop_duplicates(subset="url")

    # Target: 1 = phishing, 0 = legitimate, whatever the raw label used.
    df["is_phishing"] = (df["label"] == phishing_label_value).astype(int)
    df = df.drop(columns=["label"]).reset_index(drop=True)

    print(f"rows: {before} -> {len(df)} after cleaning (dropped nulls, empty and duplicate urls)")
    print(f"phishing share: {df['is_phishing'].mean():.3f}")
    return df


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    feature_rows = [extract_features(u) for u in df["url"]]
    features_df = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    return pd.concat([df, features_df], axis=1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, type=Path, help="raw csv file")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--url-col", default="URL")
    parser.add_argument("--label-col", default="label")
    parser.add_argument(
        "--phishing-label-value",
        type=int,
        default=0,
        help="value in the label column that means phishing (PhiUSIIL: 0, legitimate is 1; verify on the dataset page)",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = load_and_clean(args.input, args.url_col, args.label_col, args.phishing_label_value)
    df = add_features(df)

    train_df, test_df = train_test_split(
        df, test_size=args.test_size, random_state=args.seed, stratify=df["is_phishing"]
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(args.output_dir / "train.csv", index=False)
    test_df.to_csv(args.output_dir / "test.csv", index=False)
    print(f"wrote {len(train_df)} train rows and {len(test_df)} test rows to {args.output_dir}")


if __name__ == "__main__":
    main()
