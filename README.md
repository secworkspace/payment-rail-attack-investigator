# Payment Rail Attack Graph Investigator

A forensic investigation tool that reconstructs multi-stage financial fraud attacks. Not by flagging one suspicious transaction, but by tracing the full connected path an attacker took: account takeover, beneficiary manipulation, a fraudulent payment, and cash-out through an intermediary account.

Most fraud detectors score individual events in isolation. This one reconstructs the whole attack path as a connected graph and scores the chain as a unit. A login anomaly + beneficiary change + fast-approved payment caught together is a completely different signal than any one of those flags on its own.

## Screenshots

**Dashboard on load**

![Entry dashboard](<screenshots/MAIN DASHBOARD.png>)

**Live scan log — terminal animation running while the pipeline processes ACC1000**

![Scanning animation](<screenshots/SCANNING.png>)

**ACC1000 — full 4-stage attack reconstructed, score 260, HIGH RISK**

![ACC1000 investigation](<screenshots/ACC 1000 GRAPH.png>)

**ACC1020 — separate attack chain, ES to TH impossible travel + approval bypass, score 210**

![ACC1020 investigation](<screenshots/ACC 1020 GRAPH.png>)

## What it does

Detects three independent anomaly signals, each mapped to a real named security concept:

- **Impossible travel** — flags logins implying a physically impossible travel speed between two locations, using real geodesic distance calculations
- **New device login** — flags devices never previously associated with an account (device trust scoring)
- **Approval bypass** — flags payments approved suspiciously fast after creation, a TOCTOU-style control-bypass pattern

Reconstructs the full attack path as a directed graph using networkx, connecting flagged events chronologically and tracing the payment's outbound movement through intermediary accounts to a final destination.

Scores the whole path, not isolated events. A connected multi-stage chain gets a composite kill-chain multiplier applied. A 4-stage attack isn't just "4x worse" than a 1-stage flag, it's scored as a qualitatively different situation.

Labels the path using Cyber Kill Chain terminology:
```
Initial Access → Account Manipulation → Fraudulent Payment → Cash-Out
```

Verifies data integrity with a SHA-256 hash-chained audit log. Tampering with any event invalidates every subsequent hash.

Validates itself against known ground truth. The dataset includes 5 deliberately injected attack variants with different signal combinations, and validate.py computes real precision/recall/F1 per detector and system-wide.

## Validation results

Tested against 5 distinct injected attack profiles and 45 clean accounts:

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Impossible Travel | 1.00 | 0.60 | 0.75 |
| New Device Login | 1.00 | 0.80 | 0.89 |
| Approval Bypass | 1.00 | 0.60 | 0.75 |
| System (any detector) | 1.00 | 1.00 | 1.00 |

100% system-level recall. 0 false positives across 45 clean accounts.

Per-detector recall below 100% is expected and correct. Each attack variant deliberately omits one signal to test whether the system catches it through the others. See METHODOLOGY.md for the full breakdown and two real bugs found during this process.

## Architecture

```
generate_logs.py     generates the synthetic dataset with 5 injected attack variants
detect_anomalies.py  three independent anomaly detectors
attack_graph.py      builds the connected attack graph per account (networkx)
risk_scoring.py      path-level composite scoring + Cyber Kill Chain labeling
audit_log.py         SHA-256 hash-chained tamper-evident logging
validate.py          precision/recall/F1 validation against ground truth
app.py               FastAPI backend
dashboard.html       Cytoscape.js frontend with live scan log and validation report
```

Data flow:

```
generate_logs.py → synthetic_logs.json
detect_anomalies.py → individual flags
attack_graph.py → connected graph per account
risk_scoring.py → composite path score + kill-chain label
app.py → REST API
dashboard.html → graph, verdict, evidence, validation report
```

## Running locally

```bash
git clone https://github.com/<your-username>/payment-rail-attack-investigator.git
cd payment-rail-attack-investigator

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
python generate_logs.py
python validate.py           # optional, prints metrics to terminal
python app.py
```

Open `http://127.0.0.1:8000` in your browser.

## Scoring formula

```
Risk Score = sum(indicator base scores) x kill-chain stage multiplier

Impossible Travel        +40 pts
Approval Bypass          +35 pts
New Device Login         +25 pts
Fund Transfer per hop    +15 pts

1 stage    1.0x
2 stages   1.3x
3 stages   1.6x
4 stages   2.0x
```

Example from ACC1000: 40 + 25 + 35 + 30 (2 hops) = 130 base × 2.0x (4 stages) = **260**

Example from ACC1020: 40 + 35 + 30 (2 hops) = 105 base × 2.0x (4 stages) = **210**

## API

| Endpoint | Description |
|---|---|
| GET / | Dashboard |
| GET /flagged-accounts | Accounts with at least one flag |
| GET /investigate/{account_id} | Full investigation: graph, kill-chain, score |
| GET /stats | Dataset statistics |
| GET /validate | Precision / recall / F1 per detector |

Docs at `http://127.0.0.1:8000/docs`

## Stack

Python, FastAPI, networkx, geopy, Cytoscape.js, dagre, Faker

## Limitations

Uses synthetic data by design. Real authentication and payment logs aren't publicly available, so this dataset is deliberately constructed with known ground truth, which is exactly how real fraud engineering teams validate detection logic before it touches production data.

Country geolocation uses a static 75-country centroid table rather than a live IP geolocation API. The distance math is real, the simplification is in the lookup table.

Follows a single connected path per account rather than full multi-branch graphs. No streaming detection, this analyzes a static snapshot.

See METHODOLOGY.md for more on these and why some of them led to interesting bugs.

## Disclaimer

Built for educational and portfolio purposes using entirely synthetic data. Not affiliated with any financial institution.
