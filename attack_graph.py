"""
attack_graph.py

Builds a connected attack graph for a given account by combining
every event type (logins, beneficiary changes, payments, destination
transfers) into a single chronological timeline, then linking them
as nodes and edges in a directed graph — reconstructing the full
attack path rather than treating each flag in isolation.
"""

import json
import networkx as nx
from datetime import datetime

from detect_anomalies import (
    load_logs,
    detect_impossible_travel,
    detect_new_device_logins,
    detect_approval_bypass,
)


def build_account_timeline(account_id, data):
    """
    Collects every event associated with a given account — logins,
    account events, and payments — into a single chronologically
    sorted timeline. Each event is tagged with its type so the graph
    builder knows how to connect and label it.
    """
    timeline = []

    for login in data["logins"]:
        if login["account_id"] == account_id:
            timeline.append({
                "node_id": f"login-{login['timestamp']}",
                "type": "login",
                "timestamp": login["timestamp"],
                "details": login,
            })

    for event in data["account_events"]:
        if event["account_id"] == account_id:
            timeline.append({
                "node_id": f"beneficiary-{event['timestamp']}",
                "type": "beneficiary_added",
                "timestamp": event["timestamp"],
                "details": event,
            })

    for payment in data["payments"]:
        if payment["account_id"] == account_id:
            timeline.append({
                "node_id": f"payment-{payment['created_at']}",
                "type": "payment",
                "timestamp": payment["created_at"],
                "details": payment,
            })

    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def build_destination_chain(payment, data):
    """
    Follows a payment's outbound money movement through the
    destination_events (intermediary account, exchange), the same
    'follow the money' approach used in the ransomware tracer.
    """
    chain = []
    current_account = payment["beneficiary_account"]

    remaining = list(data["destination_events"])

    while True:
        next_hop = None
        for event in remaining:
            if event["from_account"] == current_account:
                next_hop = event
                break

        if next_hop is None:
            break

        chain.append(next_hop)
        remaining.remove(next_hop)
        current_account = next_hop["to_account"]

    return chain


def build_graph(timeline, destination_chain):
    """
    Constructs a directed graph connecting the account's timeline
    events in sequence, then extending it through the destination
    chain to represent the full attack path from login to cash-out.
    """
    graph = nx.DiGraph()

    for event in timeline:
        graph.add_node(event["node_id"], type=event["type"], timestamp=event["timestamp"])

    for i in range(1, len(timeline)):
        graph.add_edge(timeline[i - 1]["node_id"], timeline[i]["node_id"])

    if timeline and destination_chain:
        last_node = timeline[-1]["node_id"]
        for i, hop in enumerate(destination_chain):
            hop_node_id = f"transfer-{i}-{hop['to_account']}"
            graph.add_node(hop_node_id, type="fund_transfer", timestamp=hop["timestamp"], to_account=hop["to_account"])
            graph.add_edge(last_node, hop_node_id)
            last_node = hop_node_id

    return graph


def print_graph_summary(graph):
    print(f"\n===== ATTACK GRAPH ({graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges) =====\n")
    for node, attrs in graph.nodes(data=True):
        print(f"  [{attrs.get('type')}] {node}")
    print("\nEdges (path order):")
    for source, target in graph.edges():
        print(f"  {source}  →  {target}")


if __name__ == "__main__":
    data = load_logs()

    target_account = "ACC1000"  # the account we know has the injected attack

    timeline = build_account_timeline(target_account, data)
    print(f"Built timeline with {len(timeline)} events for {target_account}")

    target_payment = next((p for p in data["payments"] if p["account_id"] == target_account), None)
    destination_chain = build_destination_chain(target_payment, data) if target_payment else []
    print(f"Found {len(destination_chain)} destination hops")

    graph = build_graph(timeline, destination_chain)
    print_graph_summary(graph)