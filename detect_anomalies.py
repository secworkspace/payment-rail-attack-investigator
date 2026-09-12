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

# Approximate centroid coordinates for a broad set of ISO 3166-1
# alpha-2 country codes. This is intentionally NOT exhaustive -- real
# systems would use a full IP-geolocation service -- but it is large
# enough to make missing-country cases the exception rather than the
# rule. Countries not listed here are treated as genuinely unknown
# (see get_country_coords), never silently defaulted to (0, 0).
#
# IMPORTANT: (0, 0) -- "Null Island" -- is itself a real coordinate
# (in the Gulf of Guinea). Using it as a fallback for "no data" is a
# well-documented real-world GIS bug: two different unmapped countries
# would incorrectly collapse onto the same point, making genuine
# impossible-travel cases silently undetectable. This module avoids
# that by treating unmapped countries as None, not (0, 0).
COUNTRY_COORDS = {
    "US": (37.0902, -95.7129), "GB": (55.3781, -3.4360), "AU": (-25.2744, 133.7751),
    "MA": (31.7917, -7.0926), "NP": (28.3949, 84.1240), "AZ": (40.1431, 47.5769),
    "BD": (23.6850, 90.3563), "CD": (-4.0383, 21.7587), "EE": (58.5953, 25.0136),
    "ES": (40.4637, -3.7492), "GY": (4.8604, -58.9302), "IN": (20.5937, 78.9629),
    "DE": (51.1657, 10.4515), "FR": (46.2276, 2.2137), "CN": (35.8617, 104.1954),
    "RU": (61.5240, 105.3188), "BR": (-14.2350, -51.9253), "JP": (36.2048, 138.2529),
    "KE": (-0.0236, 37.9062), "MU": (-20.3484, 57.5522), "KN": (17.3578, -62.7830),
    "ME": (42.7087, 19.3744), "CA": (56.1304, -106.3468), "MX": (23.6345, -102.5528),
    "IT": (41.8719, 12.5674), "PT": (39.3999, -8.2245), "NL": (52.1326, 5.2913),
    "BE": (50.5039, 4.4699), "CH": (46.8182, 8.2275), "AT": (47.5162, 14.5501),
    "SE": (60.1282, 18.6435), "NO": (60.4720, 8.4689), "FI": (61.9241, 25.7482),
    "DK": (56.2639, 9.5018), "PL": (51.9194, 19.1451), "GR": (39.0742, 21.8243),
    "TR": (38.9637, 35.2433), "EG": (26.8206, 30.8025), "ZA": (-30.5595, 22.9375),
    "NG": (9.0820, 8.6753), "GH": (7.9465, -1.0232), "AR": (-38.4161, -63.6167),
    "CL": (-35.6751, -71.5430), "CO": (4.5709, -74.2973), "PE": (-9.1900, -75.0152),
    "VE": (6.4238, -66.5897), "SA": (23.8859, 45.0792), "AE": (23.4241, 53.8478),
    "IL": (31.0461, 34.8516), "PK": (30.3753, 69.3451), "TH": (15.8700, 100.9925),
    "VN": (14.0583, 108.2772), "ID": (-0.7893, 113.9213), "MY": (4.2105, 101.9758),
    "PH": (12.8797, 121.7740), "SG": (1.3521, 103.8198), "KR": (35.9078, 127.7669),
    "NZ": (-40.9006, 174.8860), "UA": (48.3794, 31.1656), "RO": (45.9432, 24.9668),
    "HU": (47.1625, 19.5033), "CZ": (49.8175, 15.4730), "IE": (53.4129, -8.2439),
    "AF": (33.9391, 67.7100), "IS": (64.9631, -19.0208), "CY": (35.1264, 33.4299),
    "UG": (1.3733, 32.2903), "DO": (18.7357, -70.1627), "JO": (30.5852, 36.2384),
    "RS": (44.0165, 21.0059), "UY": (-32.5228, -55.7658),
}


def get_country_coords(country_code):
    """
    Returns the approximate (latitude, longitude) for a given ISO
    country code, or None if the country is not in our reference
    table. Returning None (rather than a default like (0, 0)) is a
    deliberate choice -- see the Null Island note above. Callers must
    treat None as 'insufficient data', not as a real location.
    """
    return COUNTRY_COORDS.get(country_code)


def load_logs(filename="synthetic_logs.json"):
    """Loads the synthetic dataset produced by generate_logs.py."""
    with open(filename, "r") as f:
        return json.load(f)


def detect_impossible_travel(logins):
    """
    Groups logins by account, sorts them chronologically, and checks
    each consecutive pair for impossible travel: a required speed
    between their two locations that exceeds realistic limits.

    Pairs where either country's coordinates are unknown are skipped
    entirely -- we do not guess, and we never treat 'unknown' as if
    it were a real, shared location (see the Null Island note above).
    """
    MAX_PLAUSIBLE_SPEED_KMH = 1000

    by_account = {}
    for login in logins:
        by_account.setdefault(login["account_id"], []).append(login)

    flagged = []
    skipped_unknown_geo = 0
    skipped_codes = set()

    for account_id, account_logins in by_account.items():
        sorted_logins = sorted(account_logins, key=lambda x: x["timestamp"])

        for i in range(1, len(sorted_logins)):
            prev = sorted_logins[i - 1]
            curr = sorted_logins[i]

            if prev["country"] == curr["country"]:
                continue

            prev_coords = get_country_coords(prev["country"])
            curr_coords = get_country_coords(curr["country"])

            if prev_coords is None or curr_coords is None:
                skipped_unknown_geo += 1
                if prev_coords is None:
                    skipped_codes.add(prev["country"])
                if curr_coords is None:
                    skipped_codes.add(curr["country"])
                continue  # genuinely unknown -- do not guess

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

    if skipped_unknown_geo:
        print(f"  (Note: skipped {skipped_unknown_geo} country-change pair(s) "
              f"with no geolocation data available -- not flagged, not ignored-as-safe.)")
        print(f"  Missing country codes: {sorted(skipped_codes)}")

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