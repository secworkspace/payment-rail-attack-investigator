"""
risk_scoring.py

Path-level risk scoring for the Payment Rail Attack Graph Investigator.

Rather than scoring each anomaly in isolation, this module scores the
*connected chain* as a whole: a login + beneficiary change + payment
+ approval-bypass detected in sequence on the same account scores far
higher than four unrelated flags across four different accounts.

Also applies a Cyber Kill Chain-style label to the reconstructed path,
mapping each stage to its investigator-facing name so the dashboard
can present a plain-language narrative of how the attack unfolded.
"""

import networkx as nx

from attack_graph import build_account_timeline, build_destination_chain, build_graph
from detect_anomalies import (
    load_logs,
    detect_impossible_travel,
    detect_new_device_logins,
    detect_approval_bypass,
)


# Base risk scores assigned to each individual anomaly type.
# These reflect relative severity before any path-level amplification.
BASE_SCORES = {
    "impossible_travel": 40,
    "new_device_login":  25,
    "approval_bypass":   35,
    "beneficiary_added": 20,  # contributing stage within an attack path
    "fund_transfer":     15,  # each destination hop adds to the total
}

# When multiple stages are connected in the same account path, a
# multiplier amplifies the combined score -- a 4-stage chain is not
# just 4x one isolated event, it is disproportionately more suspicious.
PATH_MULTIPLIERS = {
    1: 1.0,
    2: 1.3,
    3: 1.6,
    4: 2.0,
}

# Maps each graph node type to its Cyber Kill Chain stage name.
# This is what surfaces on the dashboard as the plain-language narrative.
KILL_CHAIN_LABELS = {
    "login":             "Initial Access",
    "beneficiary_added": "Account Manipulation",
    "payment":           "Fraudulent Payment",
    "fund_transfer":     "Cash-Out",
}


def score_individual_flags(travel_flags, device_flags, approval_flags, account_id):
    """
    Collects all anomaly flags belonging to a specific account and
    assigns each one a base risk score from BASE_SCORES. Returns a
    list of scored flag dicts, each carrying the flag type, its base
    score, and the original flag data -- which becomes the per-stage
    evidence list on the dashboard.
    """
    scored = []

    for flag in travel_flags:
        if flag["account_id"] == account_id:
            scored.append({
                "flag_type": "impossible_travel",
                "base_score": BASE_SCORES["impossible_travel"],
                "detail": flag,
            })

    for flag in device_flags:
        if flag["account_id"] == account_id:
            scored.append({
                "flag_type": "new_device_login",
                "base_score": BASE_SCORES["new_device_login"],
                "detail": flag,
            })

    for flag in approval_flags:
        if flag["account_id"] == account_id:
            scored.append({
                "flag_type": "approval_bypass",
                "base_score": BASE_SCORES["approval_bypass"],
                "detail": flag,
            })

    return scored


def score_path(graph, scored_flags, destination_chain):
    """
    Scores the full reconstructed attack path as a composite unit.

    The base score is the sum of all individual flag scores plus a
    contribution from each destination hop (money movement). A path
    multiplier is then applied based on how many distinct event-type
    stages appear in the graph -- the more stages connected together,
    the greater the amplification, because a multi-stage chain is
    qualitatively different from a set of isolated incidents.
    """
    base_score = sum(f["base_score"] for f in scored_flags)

    # Each destination hop (intermediary account, exchange) adds to the
    # path score, reflecting that money actually moving is higher risk
    # than a payment that was merely created
    base_score += len(destination_chain) * BASE_SCORES["fund_transfer"]

    # Count distinct stage types present in the graph to pick the multiplier
    node_types = {attrs.get("type") for _, attrs in graph.nodes(data=True)}
    stage_count = len(node_types)

    # Paths with more than 4 distinct stage types cap at the 4-stage multiplier
    multiplier = PATH_MULTIPLIERS.get(stage_count, 2.0)

    final_score = round(base_score * multiplier, 1)

    return {
        "base_score": base_score,
        "stage_count": stage_count,
        "multiplier": multiplier,
        "final_score": final_score,
    }


def label_kill_chain(graph):
    """
    Walks the graph nodes in topological order (source to sink) and
    maps each node type to its Cyber Kill Chain stage name. Returns
    the reconstructed kill-chain path as an ordered list, ready to
    render as a stage-by-stage narrative on the dashboard.

    Stages are deduplicated -- if multiple login nodes exist, "Initial
    Access" still appears only once in the narrative.
    """
    kill_chain = []
    seen_labels = set()

    try:
        # Topological sort gives us source to sink order naturally
        ordered_nodes = list(nx.topological_sort(graph))
    except Exception:
        # Fall back to insertion order if the graph somehow has cycles
        ordered_nodes = list(graph.nodes())

    for node_id in ordered_nodes:
        node_type = graph.nodes[node_id].get("type")
        label = KILL_CHAIN_LABELS.get(node_type)
        if label and label not in seen_labels:
            kill_chain.append(label)
            seen_labels.add(label)

    return kill_chain


def print_risk_summary(account_id, path_result, kill_chain, scored_flags):
    """
    Prints the full risk assessment for an account's reconstructed
    attack path: the individual flags with their base scores, the
    kill-chain stage breakdown, and the final composite path score
    with its multiplier -- the same information the dashboard will
    render visually as the case verdict.
    """
    print(f"\n===== RISK SCORE SUMMARY: {account_id} =====\n")

    print("Individual flags detected:")
    for flag in scored_flags:
        marker = " [GROUND TRUTH ATTACK]" if flag["detail"].get("is_injected_attack") else ""
        print(f"  [{flag['flag_type']}]  base score: {flag['base_score']}{marker}")

    print(f"\nKill-chain path reconstructed:")
    if kill_chain:
        print("  " + "  ->  ".join(kill_chain))
    else:
        print("  (no kill-chain stages identified)")

    print(f"\nScoring breakdown:")
    print(f"  Base score (flags + hops): {path_result['base_score']}")
    print(f"  Distinct stages in path:   {path_result['stage_count']}")
    print(f"  Path multiplier applied:   {path_result['multiplier']}x")
    print(f"  Final composite score:     {path_result['final_score']}")

    # Plain-language verdict based on final score thresholds
    if path_result["final_score"] >= 150:
        verdict = "HIGH RISK -- full multi-stage attack path detected"
    elif path_result["final_score"] >= 80:
        verdict = "MEDIUM RISK -- partial attack indicators present"
    else:
        verdict = "LOW RISK -- isolated flags, no clear chain"

    print(f"\n  Verdict: {verdict}\n")


if __name__ == "__main__":
    data = load_logs()

    target_account = "ACC1000"  # the account with the injected ground-truth attack

    travel_flags   = detect_impossible_travel(data["logins"])
    device_flags   = detect_new_device_logins(data["logins"])
    approval_flags = detect_approval_bypass(data["payments"])

    scored_flags = score_individual_flags(
        travel_flags, device_flags, approval_flags, target_account
    )
    print(f"Scored {len(scored_flags)} individual flags for {target_account}")

    timeline = build_account_timeline(target_account, data)
    target_payment = next(
        (p for p in data["payments"] if p["account_id"] == target_account), None
    )
    destination_chain = build_destination_chain(target_payment, data) if target_payment else []

    graph = build_graph(timeline, destination_chain)

    path_result = score_path(graph, scored_flags, destination_chain)
    kill_chain  = label_kill_chain(graph)

    print_risk_summary(target_account, path_result, kill_chain, scored_flags)