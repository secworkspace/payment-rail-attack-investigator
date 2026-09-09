"""
detect_anomalies.py

Detection logic for the Payment Rail Attack Graph Investigator.

Implements individual anomaly-detection rules that scan the synthetic
log dataset and flag suspicious events:
  - Impossible travel: consecutive logins on the same account implying
    a physically impossible travel speed between locations.
  - New device logins: flags devices never seen before on an account.
  - Approval bypass: flags payments approved suspiciously fast after
    creation, suggesting the normal review step was skipped.

Each rule outputs flagged events with a reason and severity, which
later feed into the attack-graph construction stage.
"""

import json
from datetime import datetime
from geopy.distance import geodesic


def get_country_coords(country_code):
    """
    Returns an approximate (latitude, longitude) for a given
    ISO country code. This is a simplification — real systems would
    use precise IP geolocation — but is sufficient to demonstrate
    genuine distance/speed-based impossible travel detection.
    """
    coords = {
        "US": (37.0902, -95.7129), "GB": (55.3781, -3.4360),
        "AU": (-25.2744, 133.7751), "MA": (31.7917, -7.0926),
        "NP": (28.3949, 84.1240), "AZ": (40.1431, 47.5769),
        "BD": (23.6850, 90.3563), "CD": (-4.0383, 21.7587),
        "EE": (58.5953, 25.0136), "ES": (40.4637, -3.7492),
        "GY": (4.8604, -58.9302), "IN": (20.5937, 78.9629),
        "DE": (51.1657, 10.4515), "FR": (46.2276, 2.2137),
        "CN": (35.8617, 104.1954), "RU": (61.5240, 105.3188),
        "BR": (-14.2350, -51.9253), "JP": (36.2048, 138.2529),
    }
    return coords.get(country_code, (0.0, 0.0))


def load_logs(filename="synthetic_logs.json"):
    """Loads the synthetic dataset produced by generate_logs.py."""
    with open(filename, "r") as f:
        return json.load(f)


def detect_impossible_travel(logins):
    """
    Groups logins by account, sorts them chronologically, and checks
    each consecutive pair for impossible travel: a required speed
    between their two locations that exceeds realistic limits.
    """
    MAX_PLAUSIBLE_SPEED_KMH = 1000

    by_account = {}
    for login in logins:
        by_account.setdefault(login["account_id"], []).append(login)

    flagged = []

    for account_id, account_logins in by_account.items():
        sorted_logins = sorted(account_logins, key=lambda x: x["timestamp"])

        for i in range(1, len(sorted_logins)):
            prev = sorted_logins[i - 1]
            curr = sorted_logins[i]

            prev_coords = get_country_coords(prev["country"])
            curr_coords = get_country_coords(curr["country"])

            if prev["country"] == curr["country"]:
                continue

            distance_km = geodesic(prev_coords, curr_coords).km

            prev_time = datetime.fromisoformat(prev["timestamp"])
            curr_time = datetime.fromisoformat(curr["timestamp"])
            hours_elapsed = (curr_time - prev_time).total_seconds() / 3600

            if hours_elapsed <= 0:
                continue

            required_speed = distance_km / hours_elapsed

            if required_speed > MAX_PLAUSIBLE_SPEED_KMH:
                flagged.append({
                    "account_id": account_id,
                    "event_type": "impossible_travel",
                    "from_country": prev["country"],
                    "to_country": curr["country"],
                    "distance_km": round(distance_km, 1),
                    "hours_elapsed": round(hours_elapsed, 2),
                    "required_speed_kmh": round(required_speed, 1),
                    "flagged_login_timestamp": curr["timestamp"],
                    "is_injected_attack": curr.get("is_injected_attack", False),
                })

    return flagged


def print_flags(flagged):
    print(f"\n===== IMPOSSIBLE TRAVEL FLAGS ({len(flagged)} found) =====\n")
    for flag in flagged:
        marker = " [GROUND TRUTH ATTACK]" if flag["is_injected_attack"] else ""
        print(f"{flag['account_id']}: {flag['from_country']} → {flag['to_country']}{marker}")
        print(f"  Distance: {flag['distance_km']} km in {flag['hours_elapsed']} hours "
              f"→ required speed: {flag['required_speed_kmh']} km/h")
        print()


def detect_new_device_logins(logins):
    """
    Tracks which devices have historically been used on each account,
    and flags any login using a device never seen before for that
    account.
    """
    by_account = {}
    for login in logins:
        by_account.setdefault(login["account_id"], []).append(login)

    flagged = []

    for account_id, account_logins in by_account.items():
        sorted_logins = sorted(account_logins, key=lambda x: x["timestamp"])
        seen_devices = set()

        for login in sorted_logins:
            device = login["device_id"]

            if device not in seen_devices:
                if seen_devices:
                    flagged.append({
                        "account_id": account_id,
                        "event_type": "new_device_login",
                        "device_id": device,
                        "timestamp": login["timestamp"],
                        "is_injected_attack": login.get("is_injected_attack", False),
                    })
                seen_devices.add(device)

    return flagged


def print_device_flags(flagged):
    print(f"\n===== NEW DEVICE LOGIN FLAGS ({len(flagged)} found) =====\n")
    for flag in flagged:
        marker = " [GROUND TRUTH ATTACK]" if flag["is_injected_attack"] else ""
        print(f"{flag['account_id']}: new device {flag['device_id']}{marker}")
        print(f"  Timestamp: {flag['timestamp']}")
        print()


def detect_approval_bypass(payments):
    """
    Flags payments approved suspiciously quickly after creation —
    a signal that the normal human review/approval step may have
    been bypassed, rather than genuinely reviewed.
    """
    BYPASS_THRESHOLD_SECONDS = 60

    flagged = []

    for payment in payments:
        created = datetime.fromisoformat(payment["created_at"])
        approved = datetime.fromisoformat(payment["approved_at"])
        gap_seconds = (approved - created).total_seconds()

        if gap_seconds < BYPASS_THRESHOLD_SECONDS:
            flagged.append({
                "account_id": payment["account_id"],
                "event_type": "approval_bypass",
                "amount": payment["amount"],
                "gap_seconds": round(gap_seconds, 1),
                "created_at": payment["created_at"],
                "approved_at": payment["approved_at"],
                "is_injected_attack": payment.get("is_injected_attack", False),
            })

    return flagged


def print_approval_flags(flagged):
    print(f"\n===== APPROVAL BYPASS FLAGS ({len(flagged)} found) =====\n")
    for flag in flagged:
        marker = " [GROUND TRUTH ATTACK]" if flag["is_injected_attack"] else ""
        print(f"{flag['account_id']}: ${flag['amount']} approved in {flag['gap_seconds']}s{marker}")
        print()


if __name__ == "__main__":
    data = load_logs()

    travel_flags = detect_impossible_travel(data["logins"])
    print_flags(travel_flags)

    device_flags = detect_new_device_logins(data["logins"])
    print_device_flags(device_flags)

    approval_flags = detect_approval_bypass(data["payments"])
    print_approval_flags(approval_flags)