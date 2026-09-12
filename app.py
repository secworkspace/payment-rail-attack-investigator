"""
app.py

FastAPI backend for the Payment Rail Attack Graph Investigator.

Serves two endpoints that the dashboard consumes:
  - GET /flagged-accounts  returns every account that triggered at
    least one anomaly flag, populating the dashboard's account picker.
  - GET /investigate/{account_id}  runs the full detection-graph-
    scoring pipeline for a given account and returns the reconstructed
    case as JSON: graph nodes and edges, kill-chain stages, composite
    risk score, and per-flag evidence -- everything the dashboard needs
    in a single response.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import os
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from detect_anomalies import (
    load_logs,
    detect_impossible_travel,
    detect_new_device_logins,
    detect_approval_bypass,
)
from attack_graph import build_account_timeline, build_destination_chain, build_graph
from risk_scoring import score_individual_flags, score_path, label_kill_chain


app = FastAPI(title="Payment Rail Attack Graph Investigator")

# Allow the dashboard (served locally from a file or dev server) to
# call these endpoints without running into CORS blocks.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Load the dataset once at startup rather than re-reading the file
# on every request -- the data is static for the lifetime of this run.
_data = None

@app.get("/", response_class=FileResponse)
def serve_dashboard():
    """Serves the dashboard directly on the root URL."""
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    return FileResponse(html_path)

def get_data():
    global _data
    if _data is None:
        _data = load_logs()
    return _data


def run_all_detectors(data):
    """
    Runs all three anomaly detectors against the full dataset and
    returns their raw flag lists. Called once per investigation request
    rather than cached, so any future re-generation of logs is
    immediately reflected without restarting the server.
    """
    travel_flags   = detect_impossible_travel(data["logins"])
    device_flags   = detect_new_device_logins(data["logins"])
    approval_flags = detect_approval_bypass(data["payments"])
    return travel_flags, device_flags, approval_flags


def get_all_flagged_accounts(travel_flags, device_flags, approval_flags):
    """
    Collects the unique set of account IDs that appear in any flag
    list. This becomes the dropdown population on the dashboard --
    only accounts with at least one detected anomaly are shown.
    """
    flagged = set()
    for flag in travel_flags + device_flags + approval_flags:
        flagged.add(flag["account_id"])
    return sorted(flagged)


def graph_to_serializable(graph, data, account_id, destination_chain):
    """
    Converts the networkx DiGraph into plain dicts that FastAPI can
    serialize as JSON. Each node carries its type, timestamp, and
    whether it is part of the injected ground-truth attack -- which
    the dashboard uses to color-code attack-path nodes differently
    from normal activity nodes.
    """
    nodes = []
    edges = []

    # Build a lookup of event details keyed by node_id so we can
    # attach the original event data (including is_injected_attack)
    # to each node in the response.
    event_lookup = {}

    for login in data["logins"]:
        if login["account_id"] == account_id:
            node_id = f"login-{login['timestamp']}"
            event_lookup[node_id] = login

    for event in data["account_events"]:
        if event["account_id"] == account_id:
            node_id = f"beneficiary-{event['timestamp']}"
            event_lookup[node_id] = event

    for payment in data["payments"]:
        if payment["account_id"] == account_id:
            node_id = f"payment-{payment['created_at']}"
            event_lookup[node_id] = payment

    for i, hop in enumerate(destination_chain):
        node_id = f"transfer-{i}-{hop['to_account']}"
        event_lookup[node_id] = hop

    for node_id, attrs in graph.nodes(data=True):
        original = event_lookup.get(node_id, {})
        nodes.append({
            "id":        node_id,
            "type":      attrs.get("type"),
            "timestamp": attrs.get("timestamp"),
            "is_attack": original.get("is_injected_attack", False),
        })

    for source, target in graph.edges():
        edges.append({"source": source, "target": target})

    return nodes, edges


def get_verdict(final_score):
    """
    Converts a numeric composite score into a plain-language verdict.
    Thresholds mirror those in risk_scoring.py so the backend and
    dashboard always agree on HIGH / MEDIUM / LOW classification.
    """
    if final_score >= 150:
        return "HIGH RISK -- full multi-stage attack path detected"
    elif final_score >= 80:
        return "MEDIUM RISK -- partial attack indicators present"
    else:
        return "LOW RISK -- isolated flags, no clear chain"


@app.get("/flagged-accounts")
def flagged_accounts():
    """
    Returns the list of account IDs that triggered at least one
    anomaly flag. The dashboard calls this on load to populate
    the account picker dropdown.
    """
    data = get_data()
    travel_flags, device_flags, approval_flags = run_all_detectors(data)
    accounts = get_all_flagged_accounts(travel_flags, device_flags, approval_flags)
    return {"flagged_accounts": accounts}


@app.get("/investigate/{account_id}")
def investigate(account_id: str):
    """
    Runs the full investigation pipeline for a single account:
    anomaly detection -> graph construction -> risk scoring.
    Returns graph nodes/edges, kill-chain stages, composite score,
    and per-flag evidence as a single JSON response.
    """
    data = get_data()

    travel_flags, device_flags, approval_flags = run_all_detectors(data)

    scored_flags = score_individual_flags(
        travel_flags, device_flags, approval_flags, account_id
    )

    if not scored_flags:
        raise HTTPException(
            status_code=404,
            detail=f"{account_id} has no detected anomaly flags."
        )

    timeline = build_account_timeline(account_id, data)
    target_payment = next(
        (p for p in data["payments"] if p["account_id"] == account_id), None
    )
    destination_chain = build_destination_chain(target_payment, data) if target_payment else []

    graph = build_graph(timeline, destination_chain)

    path_result = score_path(graph, scored_flags, destination_chain)
    kill_chain  = label_kill_chain(graph)

    nodes, edges = graph_to_serializable(graph, data, account_id, destination_chain)

    return {
        "account_id": account_id,
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "kill_chain": kill_chain,
        "risk": {
            "base_score":  path_result["base_score"],
            "stage_count": path_result["stage_count"],
            "multiplier":  path_result["multiplier"],
            "final_score": path_result["final_score"],
            "verdict":     get_verdict(path_result["final_score"]),
        },
        "evidence": [
            {
                "flag_type":  f["flag_type"],
                "base_score": f["base_score"],
                "is_attack":  f["detail"].get("is_injected_attack", False),
                "detail":     f["detail"],
            }
            for f in scored_flags
        ],
    }

@app.get("/stats")
def stats():
    """
    Returns aggregate statistics about the current dataset and
    detection results -- used by the dashboard's header stat chips
    to give investigators instant situational awareness before they
    pick an account to investigate.
    """
    data = get_data()
    travel_flags, device_flags, approval_flags = run_all_detectors(data)
    flagged_accounts = get_all_flagged_accounts(travel_flags, device_flags, approval_flags)
    all_flags = travel_flags + device_flags + approval_flags

    total_events = (
        len(data["logins"]) +
        len(data["account_events"]) +
        len(data["payments"]) +
        len(data["destination_events"])
    )

    return {
        "total_events":      total_events,
        "accounts_analyzed": len(set(l["account_id"] for l in data["logins"])),
        "total_flags":       len(all_flags),
        "flagged_accounts":  len(flagged_accounts),
    }

@app.get("/validate")
def validate_system():
    """
    Runs the full validation pipeline against the known ground-truth
    attack accounts and returns per-detector and system-level
    precision/recall/F1 metrics for the dashboard's Validate tab.
    """
    from validate import (
        extract_ground_truth,
        build_flag_matrix,
        compute_metrics,
        compute_overall_metrics,
    )
    data         = get_data()
    ground_truth = extract_ground_truth(data)
    matrix       = build_flag_matrix(data)

    by_detector = {k: compute_metrics(matrix, ground_truth, k)
                   for k in ["travel", "device", "bypass"]}
    overall = compute_overall_metrics(matrix, ground_truth)

    accounts_summary = []
    for acc in sorted(matrix.keys()):
        flags   = matrix[acc]
        is_atk  = acc in ground_truth
        flagged = any(flags.values())
        if is_atk or flagged:
            accounts_summary.append({
                "account_id":     acc,
                "ground_truth":   is_atk,
                "flagged":        flagged,
                "false_positive": flagged and not is_atk,
                "detectors":      flags,
            })

    return {
        "ground_truth_accounts": sorted(ground_truth),
        "by_detector": {
            "impossible_travel": by_detector["travel"],
            "new_device_login":  by_detector["device"],
            "approval_bypass":   by_detector["bypass"],
        },
        "overall": overall,
        "accounts": accounts_summary,
    }

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)