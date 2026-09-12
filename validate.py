"""
validate.py

Validation report for the Payment Rail Attack Graph Investigator.

Runs all three anomaly detectors against the full synthetic dataset
and compares their output against the known ground-truth attack accounts
-- the ones deliberately injected at generation time. Produces a
per-account flagging table and precision/recall/F1 metrics for each
detector and the system as a whole.

This is the evidence that the system actually works rather than just
looks like it does -- the core claim of the ground-truth design.
"""

from detect_anomalies import (
    load_logs,
    detect_impossible_travel,
    detect_new_device_logins,
    detect_approval_bypass,
)


def extract_ground_truth(data):
    """
    Scans every event in the dataset for the is_injected_attack flag
    set at generation time and returns the set of account IDs that
    are known ground-truth attack accounts. This is the answer key
    the detector output is measured against.
    """
    attack_accounts = set()

    for login in data["logins"]:
        if login.get("is_injected_attack"):
            attack_accounts.add(login["account_id"])

    for event in data["account_events"]:
        if event.get("is_injected_attack"):
            attack_accounts.add(event["account_id"])

    for payment in data["payments"]:
        if payment.get("is_injected_attack"):
            attack_accounts.add(payment["account_id"])

    return attack_accounts


def build_flag_matrix(data):
    """
    Runs all three detectors and builds a dict mapping each account
    to which detectors fired on it. This becomes the rows of the
    validation table -- one account per row, one detector per column.
    """
    travel_flags   = detect_impossible_travel(data["logins"])
    device_flags   = detect_new_device_logins(data["logins"])
    approval_flags = detect_approval_bypass(data["payments"])

    all_accounts = sorted(set(l["account_id"] for l in data["logins"]))
    matrix = {acc: {"travel": False, "device": False, "bypass": False}
              for acc in all_accounts}

    for flag in travel_flags:
        matrix[flag["account_id"]]["travel"] = True
    for flag in device_flags:
        matrix[flag["account_id"]]["device"] = True
    for flag in approval_flags:
        matrix[flag["account_id"]]["bypass"] = True

    return matrix


def compute_metrics(matrix, ground_truth, detector_key):
    """
    Computes precision, recall, and F1 for a single detector.

    Precision: of the accounts flagged, what fraction were real attacks?
    Recall:    of the real attacks, what fraction did we catch?
    F1:        harmonic mean -- balances precision and recall into one number.
    """
    tp = sum(1 for acc, f in matrix.items() if f[detector_key] and acc in ground_truth)
    fp = sum(1 for acc, f in matrix.items() if f[detector_key] and acc not in ground_truth)
    fn = sum(1 for acc in ground_truth if not matrix.get(acc, {}).get(detector_key))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def compute_overall_metrics(matrix, ground_truth):
    """
    Computes system-level metrics treating any account flagged by
    at least one detector as 'flagged by the system'. An attack only
    counts as missed if zero detectors fired on it.
    """
    flagged = {acc for acc, f in matrix.items() if any(f.values())}

    tp = len(flagged & ground_truth)
    fp = len(flagged - ground_truth)
    fn = len(ground_truth - flagged)
    tn = len(set(matrix.keys()) - flagged - ground_truth)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


def print_account_table(matrix, ground_truth):
    """
    Prints the per-account flagging table. Only rows that matter are
    shown -- ground-truth attacks and any false positives. The bulk
    of clean accounts with zero flags are summarised in a single line.
    """
    print("\n===== PER-ACCOUNT FLAGGING TABLE =====\n")
    header = f"  {'Account':<12} {'Ground Truth':<16} {'Flagged?':<12} {'Travel':<8} {'Device':<8} {'Bypass'}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    clean_unflagged = 0

    for acc in sorted(matrix.keys()):
        flags   = matrix[acc]
        is_atk  = acc in ground_truth
        flagged = any(flags.values())

        # Skip clean accounts with no flags -- they are true negatives
        if not is_atk and not flagged:
            clean_unflagged += 1
            continue

        truth_str  = "ATTACK  ⚠" if is_atk else "clean"
        flag_str   = "YES (FP)" if (flagged and not is_atk) else ("YES" if flagged else "no")
        t = "✓" if flags["travel"] else "·"
        d = "✓" if flags["device"] else "·"
        b = "✓" if flags["bypass"] else "·"

        print(f"  {acc:<12} {truth_str:<16} {flag_str:<12} {t:<8} {d:<8} {b}")

    print(f"\n  ... {clean_unflagged} clean accounts with zero flags "
          f"(true negatives, omitted for brevity)\n")


def print_metrics_table(by_detector, overall):
    """
    Prints the precision/recall/F1 summary table -- the numbers that
    prove the system works as claimed and are directly quotable in
    a README or interview.
    """
    print("===== PRECISION / RECALL / F1 BY DETECTOR =====\n")
    header = f"  {'Detector':<24} {'TP':<5} {'FP':<5} {'FN':<5} {'Precision':<12} {'Recall':<10} {'F1'}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    rows = [
        ("Impossible Travel",  "travel"),
        ("New Device Login",   "device"),
        ("Approval Bypass",    "bypass"),
    ]

    for label, key in rows:
        m = by_detector[key]
        print(f"  {label:<24} {m['tp']:<5} {m['fp']:<5} {m['fn']:<5} "
              f"{m['precision']:<12.2f} {m['recall']:<10.2f} {m['f1']:.2f}")

    print("  " + "-" * (len(header) - 2))
    print(f"  {'SYSTEM (any detector)':<24} {overall['tp']:<5} {overall['fp']:<5} "
          f"{overall['fn']:<5} {overall['precision']:<12.2f} {overall['recall']:<10.2f} "
          f"{overall['f1']:.2f}")

    print(f"\n  True Negatives (clean, correctly not flagged): {overall['tn']}\n")


def print_verdict(overall, ground_truth):
    """
    Prints the plain-language conclusion: did the system catch every
    injected attack, and how many innocent accounts were falsely flagged?
    This is the sentence that goes in the README.
    """
    print("===== VALIDATION VERDICT =====\n")
    recall_pct = f"{overall['recall'] * 100:.0f}%"
    print(f"  Ground-truth attacks in dataset:    {len(ground_truth)}")
    print(f"  Correctly detected (true positives): {overall['tp']}  ({recall_pct} recall)")
    print(f"  Missed attacks (false negatives):    {overall['fn']}")
    print(f"  False alarms on clean accounts:      {overall['fp']}")

    if overall["recall"] == 1.0 and overall["fp"] == 0:
        result = "PERFECT -- all attacks caught, zero false positives"
    elif overall["recall"] == 1.0:
        result = (f"ALL ATTACKS CAUGHT -- {overall['fp']} false positive(s) "
                  f"out of {overall['tn'] + overall['fp']} clean accounts")
    elif overall["fp"] == 0:
        result = f"ZERO FALSE POSITIVES -- {overall['fn']} attack(s) missed"
    else:
        result = f"PARTIAL -- {overall['fn']} missed, {overall['fp']} false positive(s)"

    print(f"\n  Result: {result}\n")


if __name__ == "__main__":
    data = load_logs()

    ground_truth = extract_ground_truth(data)
    print(f"Ground-truth attack accounts: {sorted(ground_truth)}\n")

    matrix          = build_flag_matrix(data)
    by_detector     = {k: compute_metrics(matrix, ground_truth, k)
                       for k in ["travel", "device", "bypass"]}
    overall         = compute_overall_metrics(matrix, ground_truth)

    print_account_table(matrix, ground_truth)
    print_metrics_table(by_detector, overall)
    print_verdict(overall, ground_truth)