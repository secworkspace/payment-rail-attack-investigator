"""
generate_logs.py

Generates a synthetic dataset of financial activity logs for the
Payment Rail Attack Graph Investigator project. Creates realistic
fake accounts and layers on authentication, account, payment, and
destination events -- including several deliberately injected attack
sequences, each varying which specific signals are present, used as
ground truth for testing detection logic against more than one case.
"""

from faker import Faker
import random
import json
from datetime import datetime, timedelta

fake = Faker()

NUM_ACCOUNTS = 50


def generate_accounts(num_accounts=NUM_ACCOUNTS):
    """
    Creates a list of synthetic bank accounts, each with a fake
    account holder name, account ID, and a 'home' country/IP profile
    representing their normal, expected behavior.
    """
    accounts = []
    for i in range(num_accounts):
        account = {
            "account_id": f"ACC{1000 + i}",
            "holder_name": fake.name(),
            "home_country": fake.country_code(),
            "home_ip": fake.ipv4(),
        }
        accounts.append(account)
    return accounts


def generate_normal_logins(accounts, days=30, logins_per_account=10):
    """
    Generates normal login events for each account -- consistently
    from their home IP/country, at realistic random times over the
    given period. This represents ordinary, expected behavior.
    """
    logins = []
    start_date = datetime.now() - timedelta(days=days)

    for account in accounts:
        for _ in range(logins_per_account):
            login_time = start_date + timedelta(
                days=random.uniform(0, days),
                hours=random.uniform(0, 24)
            )
            logins.append({
                "account_id": account["account_id"],
                "event_type": "login",
                "timestamp": login_time.isoformat(),
                "ip": account["home_ip"],
                "country": account["home_country"],
                "device_id": f"device-{account['account_id']}-primary",
            })

    return logins


def generate_normal_account_events(accounts, days=30):
    """
    Generates occasional normal beneficiary-addition events for
    accounts, representing ordinary customer behavior (adding a
    new payee once in a while).
    """
    events = []
    start_date = datetime.now() - timedelta(days=days)

    accounts_with_activity = random.sample(accounts, k=len(accounts) // 3)

    for account in accounts_with_activity:
        event_time = start_date + timedelta(days=random.uniform(0, days))
        events.append({
            "account_id": account["account_id"],
            "event_type": "beneficiary_added",
            "timestamp": event_time.isoformat(),
            "beneficiary_name": fake.name(),
            "beneficiary_account": fake.iban(),
        })

    return events


def inject_one_attack(accounts, target_index, use_new_country, use_new_device, use_bypass, label):
    """
    Injects one complete attack sequence into a target account, with
    each of the three signals (impossible travel, new device, approval
    bypass) independently toggleable.

    A 'last known normal login' is inserted a short time before the
    attack login, using the account's real home country/device. This
    mirrors realistic attacker behavior -- credential theft is
    typically followed by login attempts not long after the victim's
    last genuine session -- and ensures the impossible-travel check
    has a recent, relevant prior session to compare against, rather
    than depending on chance spacing in the randomly generated normal
    login history.
    """
    target_account = accounts[target_index]
    login_time = datetime.now() - timedelta(days=random.uniform(0, 5))

    anchor_login = {
        "account_id": target_account["account_id"],
        "event_type": "login",
        "timestamp": (login_time - timedelta(minutes=random.randint(20, 90))).isoformat(),
        "ip": target_account["home_ip"],
        "country": target_account["home_country"],
        "device_id": f"device-{target_account['account_id']}-primary",
    }

    login_country = fake.country_code() if use_new_country else target_account["home_country"]
    login_device = (f"device-unknown-{random.randint(1000,9999)}" if use_new_device
                     else f"device-{target_account['account_id']}-primary")

    attack_login = {
        "account_id": target_account["account_id"],
        "event_type": "login",
        "timestamp": login_time.isoformat(),
        "ip": fake.ipv4() if use_new_country else target_account["home_ip"],
        "country": login_country,
        "device_id": login_device,
        "is_injected_attack": True,
        "attack_label": label,
    }

    beneficiary_time = login_time + timedelta(minutes=random.randint(2, 10))
    beneficiary_event = {
        "account_id": target_account["account_id"],
        "event_type": "beneficiary_added",
        "timestamp": beneficiary_time.isoformat(),
        "beneficiary_name": fake.name(),
        "beneficiary_account": fake.iban(),
        "is_injected_attack": True,
        "attack_label": label,
    }

    payment_created_time = beneficiary_time + timedelta(minutes=random.randint(1, 5))
    if use_bypass:
        payment_approved_time = payment_created_time + timedelta(seconds=random.randint(5, 30))
    else:
        # Normal approval timing -- a genuine review took place
        payment_approved_time = payment_created_time + timedelta(minutes=random.randint(10, 45))

    attack_payment = {
        "account_id": target_account["account_id"],
        "event_type": "payment",
        "created_at": payment_created_time.isoformat(),
        "approved_at": payment_approved_time.isoformat(),
        "amount": round(random.uniform(8000, 25000), 2),
        "beneficiary_account": beneficiary_event["beneficiary_account"],
        "is_injected_attack": True,
        "attack_label": label,
    }

    intermediary_account = fake.iban()
    exchange_address = f"exchange-deposit-{fake.uuid4()[:8]}"
    destination_events = [
        {
            "event_type": "fund_transfer",
            "from_account": attack_payment["beneficiary_account"],
            "to_account": intermediary_account,
            "amount": attack_payment["amount"],
            "timestamp": attack_payment["approved_at"],
            "is_injected_attack": True,
            "attack_label": label,
        },
        {
            "event_type": "fund_transfer",
            "from_account": intermediary_account,
            "to_account": exchange_address,
            "amount": round(attack_payment["amount"] * 0.97, 2),
            "timestamp": attack_payment["approved_at"],
            "is_injected_attack": True,
            "attack_label": label,
        },
    ]

    print(f"[{label}] {target_account['account_id']}: "
          f"country_change={use_new_country}, new_device={use_new_device}, bypass={use_bypass}")
    print(f"  Anchor login: {anchor_login['country']} at {anchor_login['timestamp']}")
    print(f"  Login: {login_country} / {login_device}")
    print(f"  Approval gap: {(payment_approved_time - payment_created_time).seconds}s\n")

    return anchor_login, attack_login, beneficiary_event, attack_payment, destination_events


def generate_attack_variants(accounts):
    """
    Injects several distinct attack profiles across different accounts,
    covering the full attack (all 3 signals) plus partial variants
    missing one signal each -- so validation reflects performance
    across a range of realistic attacker behavior, not just one case.
    """
    variants = [
        # (target_index, new_country, new_device, bypass, label)
        (0,  True,  True,  True,  "full_attack"),
        (10, False, True,  True,  "same_country_new_device"),
        (20, True,  False, True,  "new_country_same_device"),
        (30, True,  True,  False, "no_approval_bypass"),
        (40, False, True,  False, "device_only_weak_signal"),
    ]

    all_logins, all_beneficiaries, all_payments, all_destinations = [], [], [], []

    for target_index, new_country, new_device, bypass, label in variants:
        anchor, login, beneficiary, payment, destinations = inject_one_attack(
            accounts, target_index, new_country, new_device, bypass, label
        )
        all_logins.append(anchor)
        all_logins.append(login)
        all_beneficiaries.append(beneficiary)
        all_payments.append(payment)
        all_destinations.extend(destinations)

    return all_logins, all_beneficiaries, all_payments, all_destinations


def save_all_logs(normal_logins, normal_account_events, attack_logins,
                   attack_beneficiaries, attack_payments, destination_events,
                   filename="synthetic_logs.json"):
    """
    Combines every generated event -- normal and injected -- into a
    single dataset and saves it to disk as JSON.
    """
    dataset = {
        "logins": normal_logins + attack_logins,
        "account_events": normal_account_events + attack_beneficiaries,
        "payments": attack_payments,
        "destination_events": destination_events,
    }

    with open(filename, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"Saved full dataset to {filename}")
    print(f"  Logins: {len(dataset['logins'])}")
    print(f"  Account events: {len(dataset['account_events'])}")
    print(f"  Payments: {len(dataset['payments'])}")
    print(f"  Destination events: {len(dataset['destination_events'])}")


if __name__ == "__main__":
    accounts = generate_accounts()
    print(f"Generated {len(accounts)} accounts.\n")

    normal_logins = generate_normal_logins(accounts)
    print(f"Generated {len(normal_logins)} normal login events.\n")

    normal_account_events = generate_normal_account_events(accounts)
    print(f"Generated {len(normal_account_events)} normal beneficiary events.\n")

    print("Injecting attack variants...\n")
    attack_logins, attack_beneficiaries, attack_payments, destination_events = generate_attack_variants(accounts)

    save_all_logs(normal_logins, normal_account_events, attack_logins,
                  attack_beneficiaries, attack_payments, destination_events)