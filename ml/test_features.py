"""Tests for features.py. Run from the ml/ folder with:  python -m pytest -q
The expected numbers were taken from the C# UrlFeatureExtractor so both stay in sync.
"""

import pytest

from features import FEATURE_NAMES, extract_features, feature_vector


def test_all_feature_names_are_always_present():
    features = extract_features("https://www.example.com/")
    assert list(features.keys()) == FEATURE_NAMES


def test_normal_https_url():
    url = "https://www.example.com/a/b?x=1&y=2"
    f = extract_features(url)
    assert f["url_length"] == 35
    assert f["host_length"] == 15
    assert f["num_dots"] == 2
    assert f["num_digits"] == 2
    assert f["num_subdomains"] == 1
    assert f["is_https"] == 1
    assert f["num_query_params"] == 2
    assert f["path_depth"] == 2
    assert f["special_char_count"] == 11
    assert f["has_suspicious_keyword"] == 0
    assert f["digit_ratio"] == pytest.approx(2 / 35)


def test_ip_host_with_login_keyword():
    f = extract_features("http://192.168.0.1/login")
    assert f["is_https"] == 0
    assert f["has_ip_host"] == 1
    assert f["num_subdomains"] == 0
    assert f["has_suspicious_keyword"] == 1
    assert f["host_length"] == 11
    assert f["num_digits"] == 8


def test_at_symbol_and_punycode():
    f = extract_features("https://paypal.com@xn--pple-43d.com/")
    assert f["has_at_symbol"] == 1
    assert f["has_punycode"] == 1
    assert f["host_length"] == 16
    assert f["num_hyphens"] == 3


def test_unparseable_url_only_sets_length():
    f = extract_features("not a url")
    assert f["url_length"] == 9
    assert sum(v for k, v in f.items() if k != "url_length") == 0


def test_feature_vector_matches_name_order():
    url = "https://secure-login.account-verify.example.com/signin?id=1"
    vector = feature_vector(url)
    features = extract_features(url)
    assert vector == [features[name] for name in FEATURE_NAMES]
    assert len(vector) == len(FEATURE_NAMES)


def test_none_is_rejected():
    with pytest.raises(ValueError):
        extract_features(None)
