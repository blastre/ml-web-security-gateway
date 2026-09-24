# Phase 1 Evaluation Report

ML-Assisted Web Security Gateway - SSRF detection models

*Generated 2026-09-24T08:15:11+00:00 (UTC). This file is produced by `python -m mlwsg evaluate`; do not edit by hand.*

## 1. Setup

| Property | Value |
|---|---|
| Dataset | `data/ssrf_dataset.csv` |
| Samples | 12,000 |
| Train / test | 8,400 / 3,600 (stratified by family) |
| Test label counts | benign=2,160, ssrf=1,440 |
| Traffic families | 47 |
| Features per request | 81 |
| Positive class | `ssrf` |

## 2. Headline results (held-out test set)

| Model | Precision | Recall | F1 | FPR | Accuracy | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| `isolation_forest` | 0.8221 | 0.8854 | 0.8526 | 0.1278 | 0.8775 | 0.9121 | 0.8301 |
| `logistic_regression` | 0.9845 | 0.9694 | 0.9769 | 0.0102 | 0.9817 | 0.9976 | 0.9969 |
| `random_forest` | 0.9929 | 0.9681 | 0.9803 | 0.0046 | 0.9844 | 0.9988 | 0.9983 |

*FPR is the share of benign requests that would be blocked -- the number that decides whether a gateway can run inline.*

## 3. Confusion matrices

| Model | TN (benign allowed) | FP (benign blocked) | FN (attack missed) | TP (attack blocked) |
|---|---|---|---|---|
| `isolation_forest` | 1884 | 276 | 165 | 1275 |
| `logistic_regression` | 2138 | 22 | 44 | 1396 |
| `random_forest` | 2150 | 10 | 46 | 1394 |

## 4. Prediction latency

| Model | Mean (ms) | Median (ms) | p95 (ms) | p99 (ms) | Batched (ms/req) | Single-request throughput (req/s) |
|---|---|---|---|---|---|---|
| `isolation_forest` | 4.293 | 4.257 | 4.659 | 4.881 | 0.1396 | 233 |
| `logistic_regression` | 0.282 | 0.267 | 0.371 | 0.401 | 0.1166 | 3,551 |
| `random_forest` | 2.127 | 2.115 | 2.320 | 2.427 | 0.1304 | 470 |

*Measured end to end: URL normalisation, feature extraction and inference, one request at a time, as an inline gateway would call it.*

## 5. Cross-validation (5-fold, training split)

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| `logistic_regression` | 0.9805 +/- 0.0077 | 0.9690 +/- 0.0037 | 0.9747 +/- 0.0036 | 0.0129 +/- 0.0052 |
| `random_forest` | 0.9908 +/- 0.0019 | 0.9613 +/- 0.0042 | 0.9758 +/- 0.0022 | 0.0060 +/- 0.0013 |

## 6. Isolation Forest (anomaly detection)

The Isolation Forest is fitted on **benign traffic only** and never sees a labelled attack. It is evaluated against the same labelled test set, which measures the thing that matters for Phase 2: how much of the attack surface is recoverable without knowing the attack in advance.

**`isolation_forest`** - trained on 4,032 benign samples, tuned threshold `0.0612` (validation split of the training data).

| Decision rule | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Tuned threshold (0.0612) | 0.8221 | 0.8854 | 0.8526 | 0.1278 |
| Default `contamination` cut-off | 0.8603 | 0.4576 | 0.5975 | 0.0495 |

Mean anomaly score: benign `0.1270` vs SSRF `0.0127` (lower = more anomalous). Ranking quality is better read from ROC-AUC `0.9121` than from the thresholded scores.

## 7. Detection rate per attack family

Recall broken down by technique. A family at 1.0000 is fully covered; anything lower is a concrete gap for Phase 2's deterministic rules to close.

| Attack family | n | `isolation_forest` | `logistic_regression` | `random_forest` |
|---|---|---|---|---|
| `ssrf_alt_scheme` | 60 | 0.6333 | 1.0000 | 1.0000 |
| `ssrf_backslash_obfuscation` | 38 | 0.8947 | 1.0000 | 1.0000 |
| `ssrf_body_payload` | 49 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_case_and_trailing_dot` | 38 | 0.8684 | 1.0000 | 1.0000 |
| `ssrf_cgnat_shared` | 33 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_decimal_ip` | 47 | 0.9787 | 1.0000 | 1.0000 |
| `ssrf_dns_embedded_ip` | 54 | 0.9630 | 1.0000 | 1.0000 |
| `ssrf_dns_rebinding` | 44 | 0.0000 | 0.2727 | 0.2500 |
| `ssrf_double_encoded` | 44 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_hex_ip` | 51 | 0.9020 | 1.0000 | 1.0000 |
| `ssrf_internal_hostname` | 88 | 0.9205 | 1.0000 | 1.0000 |
| `ssrf_internal_port_probe` | 59 | 0.9661 | 1.0000 | 1.0000 |
| `ssrf_ipv6_loopback` | 49 | 0.9796 | 1.0000 | 1.0000 |
| `ssrf_ipv6_unique_local` | 38 | 0.9737 | 1.0000 | 1.0000 |
| `ssrf_link_local_metadata` | 81 | 0.8395 | 1.0000 | 1.0000 |
| `ssrf_loopback_direct` | 97 | 0.9485 | 1.0000 | 1.0000 |
| `ssrf_metadata_via_redirect` | 46 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_octal_ip` | 46 | 0.9130 | 1.0000 | 1.0000 |
| `ssrf_open_redirect_param` | 72 | 0.7917 | 1.0000 | 1.0000 |
| `ssrf_percent_encoded` | 46 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_private_network` | 95 | 0.9789 | 1.0000 | 1.0000 |
| `ssrf_redirect_chain` | 67 | 0.6716 | 0.8209 | 0.8060 |
| `ssrf_short_ip` | 45 | 0.9556 | 1.0000 | 1.0000 |
| `ssrf_unicode_obfuscation` | 36 | 1.0000 | 1.0000 | 1.0000 |
| `ssrf_unspecified_address` | 35 | 0.9429 | 1.0000 | 1.0000 |
| `ssrf_userinfo_confusion` | 51 | 0.8824 | 1.0000 | 1.0000 |
| `ssrf_whitespace_obfuscation` | 31 | 1.0000 | 1.0000 | 1.0000 |

## 8. False positives per benign family

The benign families marked *hard negative* are adversarial by design: public IP literals, encoded search text, non-standard ports, and internal URLs quoted inside free-text fields.

| Benign family | n | `isolation_forest` | `logistic_regression` | `random_forest` |
|---|---|---|---|---|
| `benign_api_call` | 227 | 0.0000 | 0.0000 | 0.0000 |
| `benign_cdn_image_resize` | 83 | 0.0000 | 0.0000 | 0.0000 |
| `benign_dev_referrer` | 63 | 0.2698 | 0.0000 | 0.0000 |
| `benign_encoded_path` | 84 | 0.0000 | 0.0000 | 0.0000 |
| `benign_form_post` | 91 | 0.0000 | 0.0000 | 0.0000 |
| `benign_internal_url_as_text` | 83 | 0.6506 | 0.0361 | 0.0000 |
| `benign_long_query` | 96 | 0.0104 | 0.0000 | 0.0000 |
| `benign_mentions_internal` | 94 | 0.0000 | 0.0000 | 0.0000 |
| `benign_oauth_callback` | 83 | 0.1446 | 0.0000 | 0.0000 |
| `benign_pagination` | 94 | 0.0000 | 0.0000 | 0.0000 |
| `benign_public_high_port` | 92 | 0.0326 | 0.0000 | 0.0000 |
| `benign_public_ip_literal` | 119 | 1.0000 | 0.0000 | 0.0000 |
| `benign_public_redirect` | 99 | 0.0101 | 0.1313 | 0.1010 |
| `benign_punycode_host` | 63 | 0.0000 | 0.0000 | 0.0000 |
| `benign_rss_feed` | 68 | 0.0000 | 0.0000 | 0.0000 |
| `benign_search` | 154 | 0.0714 | 0.0000 | 0.0000 |
| `benign_static_asset` | 226 | 0.0000 | 0.0000 | 0.0000 |
| `benign_url_param_public` | 180 | 0.3167 | 0.0333 | 0.0000 |
| `benign_userinfo_public` | 72 | 0.0000 | 0.0000 | 0.0000 |
| `benign_webhook_public` | 89 | 0.0112 | 0.0000 | 0.0000 |

## 9. What the models learned

**Random Forest - top features by impurity importance**

| Rank | Feature | Importance |
|---|---|---|
| 1 | `internal_destination_count` | 0.2142 |
| 2 | `any_destination_internal` | 0.1852 |
| 3 | `redirect_param_target_is_internal` | 0.0731 |
| 4 | `dest_is_internal` | 0.0679 |
| 5 | `url_digit_ratio` | 0.0352 |
| 6 | `scheme_is_https` | 0.0316 |
| 7 | `redirect_param_target_is_ip` | 0.0287 |
| 8 | `scheme_is_http` | 0.0258 |
| 9 | `num_query_params` | 0.0246 |
| 10 | `path_has_fetch_marker` | 0.0244 |
| 11 | `has_redirect_param` | 0.0227 |
| 12 | `url_decoded_length` | 0.0195 |
| 13 | `dest_is_private` | 0.0172 |
| 14 | `path_length` | 0.0172 |
| 15 | `host_digit_ratio` | 0.0169 |

**Logistic Regression - largest absolute coefficients** (on standardised features)

| Rank | Feature | Coefficient | Pushes towards |
|---|---|---|---|
| 1 | `num_query_params` | -2.7590 | benign |
| 2 | `redirect_param_target_is_internal` | +2.5927 | ssrf |
| 3 | `dest_is_public` | -2.3898 | benign |
| 4 | `path_has_fetch_marker` | +2.3867 | ssrf |
| 5 | `host_digit_ratio` | +2.3311 | ssrf |
| 6 | `url_digit_ratio` | +1.9406 | ssrf |
| 7 | `decode_rounds` | -1.6894 | benign |
| 8 | `redirect_target_is_internal` | +1.6069 | ssrf |
| 9 | `path_depth` | +1.4874 | ssrf |
| 10 | `has_encoded_slash` | +1.4336 | ssrf |
| 11 | `path_length` | -1.3601 | benign |
| 12 | `body_target_is_internal` | +1.2863 | ssrf |
| 13 | `dest_is_internal` | +1.2650 | ssrf |
| 14 | `embedded_url_count` | -1.2568 | benign |
| 15 | `dest_is_private` | +0.8752 | ssrf |

## 10. Reading these numbers honestly

- **The dataset is synthetic.** It is generated from a family registry, so every attack in the test set is a variation of an attack in the training set. Scores here are an upper bound on what the same models would do against live traffic.
- **The feature extractor does most of the work.** URL normalisation, permissive IP parsing and destination classification are deterministic; the models mostly learn how to weigh those signals against each other. That is intentional -- it is also why the per-family table matters more than the headline F1.
- **The genuinely hard cases are the ambiguous benign families.** `benign_internal_url_as_text` and `benign_dev_referrer` contain a real internal URL inside a harmless request. Separating them from `ssrf_open_redirect_param` needs the *interaction* between 'an internal URL is present' and 'it sits in a fetch parameter on a fetch endpoint' -- which is where the tree ensemble earns its place over the linear model.
- **Resolution-time attacks are out of scope for Phase 1.** A hostname that looks public and resolves to 10.0.0.5 (DNS rebinding) cannot be caught from the URL string. That is exactly the job of the Phase 2 egress guard.

