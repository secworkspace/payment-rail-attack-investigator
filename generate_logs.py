"""
generate_logs.py

Generates a synthetic dataset of financial activity logs for the
Payment Rail Attack Graph Investigator project. Creates realistic
fake accounts and, in later steps, layers on authentication, account,
payment, and destination events — including deliberately injected
attack sequences used as ground truth for testing detection logic.
"""

from faker import Faker
import random
import json

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

from datetime import datetime, timedelta

def generate_normal_logins(accounts, days=30, logins_per_account=10):
    """
    Generates normal login events for each account — consistently
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


def inject_attack_login(accounts, logins, target_index=0):
    """
    Injects one suspicious login into a target account's history:
    a login from a completely different country/IP/device than that
    account's normal pattern, at a specific recent time. This is the
    'ground truth' attack event our detection logic should catch.
    """
    target_account = accounts[target_index]

    attack_login = {
        "account_id": target_account["account_id"],
        "event_type": "login",
        "timestamp": datetime.now().isoformat(),
        "ip": fake.ipv4(),  # a brand-new, unrelated IP
        "country": fake.country_code(),  # different from home_country
        "device_id": f"device-unknown-{random.randint(1000,9999)}",
        "is_injected_attack": True,  # marks this as ground truth for later validation
    }

    logins.append(attack_login)
    print(f"Injected attack login into {target_account['account_id']} "
          f"({target_account['home_country']} → {attack_login['country']})")

    return attack_login 

def generate_normal_account_events(accounts, days=30):
    """
    Generates occasional normal beneficiary-addition events for
    accounts, representing ordinary customer behavior (adding a
    new payee once in a while).
    """
    events = []
    start_date = datetime.now() - timedelta(days=days)

    # Only some accounts add a beneficiary during this period — not all
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


def inject_attack_sequence(accounts, attack_login, target_index=0):
    """
    Given the injected attack login, builds the rest of the attack
    chain: a beneficiary added shortly after the suspicious login,
    followed by a payment created and approved suspiciously fast
    (simulating an approval-bypass), completing the ground-truth
    attack sequence.
    """
    target_account = accounts[target_index]
    login_time = datetime.fromisoformat(attack_login["timestamp"])

    # Beneficiary added just minutes after the suspicious login
    beneficiary_time = login_time + timedelta(minutes=random.randint(2, 10))
    beneficiary_event = {
        "account_id": target_account["account_id"],
        "event_type": "beneficiary_added",
        "timestamp": beneficiary_time.isoformat(),
        "beneficiary_name": fake.name(),
        "beneficiary_account": fake.iban(),
        "is_injected_attack": True,
    }

    # Payment created shortly after the beneficiary is added
    payment_created_time = beneficiary_time + timedelta(minutes=random.randint(1, 5))
    # Payment "approved" almost immediately — simulating a bypassed approval step
    payment_approved_time = payment_created_time + timedelta(seconds=random.randint(5, 30))

    payment_event = {
        "account_id": target_account["account_id"],
        "event_type": "payment",
        "created_at": payment_created_time.isoformat(),
        "approved_at": payment_approved_time.isoformat(),
        "amount": round(random.uniform(8000, 25000), 2),
        "beneficiary_account": beneficiary_event["beneficiary_account"],
        "is_injected_attack": True,
    }

    print(f"Injected beneficiary change + payment for {target_account['account_id']}")
    print(f"  Beneficiary added: {beneficiary_time}")
    print(f"  Payment created:   {payment_created_time}")
    print(f"  Payment approved:  {payment_approved_time} "
          f"(gap: {(payment_approved_time - payment_created_time).seconds}s)")

    return beneficiary_event, payment_event 



def inject_destination_chain(attack_payment):
    """
    Simulates the final stage of the attack: the fraudulent payment
    moving through an intermediary account before reaching a
    crypto exchange deposit address — completing the full attack
    chain from initial login to cash-out.
    """
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
        },
        {
            "event_type": "fund_transfer",
            "from_account": intermediary_account,
            "to_account": exchange_address,
            "amount": round(attack_payment["amount"] * 0.97, 2),  # minor fee/skim
            "timestamp": attack_payment["approved_at"],
            "is_injected_attack": True,
        },
    ]

    print(f"  Intermediary: {intermediary_account}")
    print(f"  Final destination (exchange): {exchange_address}")

    return destination_events


def save_all_logs(logins, account_events, attack_login, attack_beneficiary, attack_payment, destination_events, filename="synthetic_logs.json"):
    """
    Combines every generated event into a single dataset and saves
    it to disk as JSON, ready for the detection and graph-building
    stages to consume.
    """
    all_logins = logins + [attack_login]
    all_account_events = account_events + [attack_beneficiary]
    all_payments = [attack_payment]

    dataset = {
        "logins": all_logins,
        "account_events": all_account_events,
        "payments": all_payments,
        "destination_events": destination_events,
    }

    with open(filename, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"\nSaved full dataset to {filename}")
    print(f"  Logins: {len(all_logins)}")
    print(f"  Account events: {len(all_account_events)}")
    print(f"  Payments: {len(all_payments)}")
    print(f"  Destination events: {len(destination_events)}")

if __name__ == "__main__":
    accounts = generate_accounts()
    print(f"Generated {len(accounts)} accounts.\n")

    logins = generate_normal_logins(accounts)
    print(f"Generated {len(logins)} normal login events.\n")

    attack_login = inject_attack_login(accounts, logins, target_index=0)
    print(f"Attack login: {attack_login}\n")

    account_events = generate_normal_account_events(accounts)
    print(f"Generated {len(account_events)} normal beneficiary events.\n")

    attack_beneficiary, attack_payment = inject_attack_sequence(accounts, attack_login, target_index=0)

    destination_events = inject_destination_chain(attack_payment)

    save_all_logs(logins, account_events, attack_login, attack_beneficiary, attack_payment, destination_events)