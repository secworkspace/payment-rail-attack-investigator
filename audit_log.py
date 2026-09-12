"""
audit_log.py

Hash-chained audit logger for the Payment Rail Attack Graph Investigator.

Wraps every event in the synthetic dataset with a SHA-256 hash that
links it to the previous event's hash — the same tamper-evident
chain principle used in certificate transparency logs and blockchain
ledgers. If any event is altered after the fact, every subsequent
hash in the chain will no longer match, making tampering detectable.

Reads the raw synthetic_logs.json produced by generate_logs.py and
writes a new hash-chained version to audit_log.json, which all later
stages (anomaly detection, graph building) can treat as the canonical,
integrity-verified source of truth.
"""

import json
import hashlib
from datetime import datetime


# The hash of the very first event has no real predecessor, so we
# use a fixed genesis string as the starting point -- the same
# convention used in blockchain genesis blocks.
GENESIS_HASH = "0" * 64


def hash_event(event_data, prev_hash):
    """
    Computes a SHA-256 hash for a single event by combining the
    previous hash with the event's own content. This creates the
    chain: each event's hash depends on everything that came before
    it, so a change anywhere propagates forward and breaks all
    subsequent hashes.
    """
    chain_input = prev_hash + json.dumps(event_data, sort_keys=True)
    return hashlib.sha256(chain_input.encode()).hexdigest()


def flatten_all_events(data):
    """
    Merges all event types (logins, account events, payments,
    destination transfers) into a single chronologically sorted
    list. The hash chain spans the entire dataset -- not just one
    event type -- so tampering with any category breaks the chain.
    """
    all_events = []

    for event in data["logins"]:
        all_events.append({"category": "login", "event": event,
                            "sort_key": event.get("timestamp", "")})

    for event in data["account_events"]:
        all_events.append({"category": "account_event", "event": event,
                            "sort_key": event.get("timestamp", "")})

    for event in data["payments"]:
        all_events.append({"category": "payment", "event": event,
                            "sort_key": event.get("created_at", "")})

    for event in data["destination_events"]:
        all_events.append({"category": "destination", "event": event,
                            "sort_key": event.get("timestamp", "")})

    all_events.sort(key=lambda x: x["sort_key"])
    return all_events


def build_audit_chain(all_events):
    """
    Iterates through every event in chronological order and wraps
    each one in an audit record: the original event data, the
    previous hash it was chained against, and the resulting hash
    of this entry. The first record chains against GENESIS_HASH.
    """
    chain = []
    prev_hash = GENESIS_HASH

    for entry in all_events:
        current_hash = hash_event(entry["event"], prev_hash)

        chain.append({
            "seq": len(chain),                     # sequential position in the chain
            "category": entry["category"],
            "event": entry["event"],
            "prev_hash": prev_hash,
            "hash": current_hash,
        })

        prev_hash = current_hash

    return chain


def verify_chain(chain):
    """
    Re-computes every hash in the audit chain from scratch and
    compares it against the stored hash. Returns True if the chain
    is intact, or reports the first broken link if tampering is
    detected -- giving investigators the exact record where the
    audit trail was compromised.
    """
    expected_prev = GENESIS_HASH

    for record in chain:
        recomputed = hash_event(record["event"], expected_prev)

        if recomputed != record["hash"]:
            print(f"  [TAMPER DETECTED] Chain broken at seq {record['seq']} "
                  f"(category: {record['category']})")
            print(f"  Expected: {recomputed[:16]}...")
            print(f"  Stored:   {record['hash'][:16]}...")
            return False

        expected_prev = record["hash"]

    return True


def save_audit_log(chain, filename="audit_log.json"):
    """
    Saves the full hash-chained audit log to disk. This file becomes
    the tamper-evident record of the entire dataset -- any downstream
    stage can call verify_chain() on it before trusting the data.
    """
    output = {
        "generated_at": datetime.now().isoformat(),
        "total_records": len(chain),
        "chain": chain,
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Saved audit log to {filename}  ({len(chain)} records chained)")


def print_chain_summary(chain):
    print(f"\n===== AUDIT CHAIN SUMMARY ({len(chain)} records) =====\n")
    for record in chain[:5]:  # show first 5 so output stays readable
        is_attack = record["event"].get("is_injected_attack", False)
        marker = "  [GROUND TRUTH ATTACK]" if is_attack else ""
        print(f"  seq {record['seq']:03d}  [{record['category']}]  "
              f"hash: {record['hash'][:16]}...{marker}")
    if len(chain) > 5:
        print(f"  ... ({len(chain) - 5} more records)")
    print()


if __name__ == "__main__":
    with open("synthetic_logs.json", "r") as f:
        data = json.load(f)

    print(f"Loaded dataset: "
          f"{len(data['logins'])} logins, "
          f"{len(data['account_events'])} account events, "
          f"{len(data['payments'])} payments, "
          f"{len(data['destination_events'])} destination events\n")

    all_events = flatten_all_events(data)
    print(f"Flattened and sorted {len(all_events)} total events\n")

    chain = build_audit_chain(all_events)
    print_chain_summary(chain)

    print("Verifying chain integrity...")
    intact = verify_chain(chain)
    if intact:
        print(f"  Chain intact -- all {len(chain)} hashes verified\n")

    save_audit_log(chain)