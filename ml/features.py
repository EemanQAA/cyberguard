"""URL feature extraction for the CyberGuard phishing model.

IMPORTANT: this file must stay identical in behaviour to
src/CyberGuard.Domain/Engines/UrlFeatureExtractor.cs (Maha's C# extractor). The model is
trained on the values produced here and, in production, receives the values produced by
the C# code. If the two differ, predictions are wrong ("training/serving skew").
If you add, remove or reorder a feature, change BOTH files and their tests.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Same names and same order as UrlFeatureExtractor.FeatureNames in C#.
FEATURE_NAMES = [
    "url_length",
    "host_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "is_https",
    "has_at_symbol",
    "has_ip_host",
    "has_punycode",
    "num_query_params",
    "path_depth",
    "special_char_count",
    "has_suspicious_keyword",
]

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "confirm", "account", "signin", "banking"]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_features(raw_url: str) -> dict[str, float]:
    """Return every feature in FEATURE_NAMES for one URL.

    If the URL cannot be parsed (no scheme or no host), only url_length is set and the
    rest are 0, exactly like the C# version.
    """
    if raw_url is None:
        raise ValueError("raw_url must not be None")

    features = {name: 0.0 for name in FEATURE_NAMES}
    features["url_length"] = float(len(raw_url))

    try:
        parsed = urlparse(raw_url)
        host = parsed.hostname  # lower-cased, without user info and port
    except ValueError:
        return features

    if not parsed.scheme or not host:
        return features

    digit_count = sum(ch.isdigit() for ch in raw_url)
    is_ip_host = bool(_IP_RE.match(host))

    features["host_length"] = float(len(host))
    features["num_dots"] = float(raw_url.count("."))
    features["num_hyphens"] = float(raw_url.count("-"))
    features["num_digits"] = float(digit_count)
    features["digit_ratio"] = digit_count / len(raw_url) if raw_url else 0.0
    # An IP address has dots but no subdomains, so it counts as 0.
    features["num_subdomains"] = 0.0 if is_ip_host else float(max(0, len(host.split(".")) - 2))
    features["is_https"] = 1.0 if parsed.scheme.lower() == "https" else 0.0
    features["has_at_symbol"] = 1.0 if "@" in raw_url else 0.0
    features["has_ip_host"] = 1.0 if is_ip_host else 0.0
    features["has_punycode"] = 1.0 if "xn--" in host.lower() else 0.0
    features["num_query_params"] = float(len([p for p in parsed.query.split("&") if p])) if parsed.query else 0.0
    features["path_depth"] = float(len([seg for seg in parsed.path.split("/") if seg]))
    features["special_char_count"] = float(sum(not ch.isalnum() for ch in raw_url))
    lowered = raw_url.lower()
    features["has_suspicious_keyword"] = 1.0 if any(k in lowered for k in SUSPICIOUS_KEYWORDS) else 0.0

    return features


def feature_vector(raw_url: str) -> list[float]:
    """Features as a list in FEATURE_NAMES order (what the model consumes)."""
    values = extract_features(raw_url)
    return [values[name] for name in FEATURE_NAMES]
