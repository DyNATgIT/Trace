"""Deterministic synthetic bank dataset.

Builds a believable payments graph with two planted fraud patterns that a
human (and a weak model) can miss by looking at single accounts, but that are
obvious once you follow the connections:

  * RING A  "device ring"   — 8 recently-opened retail accounts, 3 shared
    devices, 2 shared datacenter-ish IPs, high-value electronics purchases in
    a 36h burst, funded by one external account, drained through 5 business
    "mule" accounts into 2 external accounts.
  * RING B  "card testing"  — 12 accounts, 3 shared devices, 2 shared IPs,
    ~60 tiny FAILED authorizations in a 6h window spread across many
    merchants, then a few successful purchases on 2 of the accounts.

Everything else is innocent: ~150 regular retail accounts with their own
device, their own home IP, and normal spending history.

`time` values are days (float, 0..90) so span math is trivial in Cypher.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Dataset:
    accounts: list[dict] = field(default_factory=list)
    merchants: list[dict] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    ips: list[dict] = field(default_factory=list)
    txns: list[dict] = field(default_factory=list)
    made: list[dict] = field(default_factory=list)        # account, txn
    on_device: list[dict] = field(default_factory=list)   # txn, device
    from_ip: list[dict] = field(default_factory=list)     # txn, ip
    at: list[dict] = field(default_factory=list)          # txn, merchant
    funds: list[dict] = field(default_factory=list)       # from, to, amount, time
    policies: list[dict] = field(default_factory=list)
    runbooks: list[dict] = field(default_factory=list)
    teams: list[dict] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)
    policy_runbook: list[dict] = field(default_factory=list)
    policy_team: list[dict] = field(default_factory=list)
    incident_policy: list[dict] = field(default_factory=list)

    def stats(self) -> dict[str, int]:
        return {
            "accounts": len(self.accounts),
            "merchants": len(self.merchants),
            "devices": len(self.devices),
            "ips": len(self.ips),
            "txns": len(self.txns),
            "funding_edges": len(self.funds),
            "policies": len(self.policies),
        }


RING_A = ["A-1042", "A-1043", "A-1044", "A-1045", "A-1051", "A-1052", "A-1060", "A-1061"]
RING_B = [f"A-{1100 + i}" for i in range(12)]
MULES = [f"A-{1200 + i}" for i in range(5)]
EXTERNALS = ["E-9001", "E-9002", "E-9003"]


def generate(seed: int = 42) -> Dataset:
    rng = random.Random(seed)
    ds = Dataset()

    # ---------------------------------------------------------------- merchants
    categories = ["grocery", "electronics", "travel", "cafe", "gaming",
                  "fuel", "pharmacy", "clothing", "hardware", "telecom"]
    for i in range(40):
        ds.merchants.append({"name": f"M-{i:03d}", "category": categories[i % len(categories)]})
    ring_a_merchants = ["M-004", "M-009", "M-020"]  # electronics-heavy
    card_test_merchants = [f"M-{i:03d}" for i in range(15)]

    # ---------------------------------------------------------------- accounts
    def acct(name: str, tier: str, opened: float) -> None:
        ds.accounts.append({"name": name, "tier": tier, "opened": round(opened, 1)})

    all_regular = [f"A-{1000 + i}" for i in range(180)]
    for a in all_regular:
        if a in RING_A:
            acct(a, "retail", rng.uniform(10, 14))      # ring A: recently opened
        elif a in RING_B:
            acct(a, "retail", rng.uniform(2, 9))        # ring B: brand new
        else:
            acct(a, "retail", rng.uniform(1, 60))
    for a in MULES:
        acct(a, "business", rng.uniform(0.5, 3))
    for a in EXTERNALS:
        acct(a, "external", 0.0)

    # ---------------------------------------------------------------- devices/ips
    # 165 personal devices: regular accounts get a UNIQUE device each (index-based),
    # so device-sharing is only ever a real signal (rings use the shared D-9xx pool).
    for i in range(165):
        ds.devices.append({"name": f"D-{100 + i:03d}", "kind": rng.choice(["phone", "laptop", "tablet"])})
    for i, kind in enumerate(["shared", "shared", "shared", "shared", "shared", "shared"]):
        ds.devices.append({"name": f"D-{901 + i}", "kind": kind})
    for i in range(40):
        ds.ips.append({"name": f"203.0.{i // 10}.{(i * 7) % 250 + 2}"})
    for name in ["185.220.101.14", "185.220.101.15", "91.215.85.6", "91.215.85.7"]:
        ds.ips.append({"name": name})

    # ---------------------------------------------------------------- txns
    _tid = 0

    def txn(t: float, amount: float, status: str) -> str:
        nonlocal _tid
        _tid += 1
        tid = f"TXN-{_tid:05d}"
        ds.txns.append({"id": tid, "time": round(t, 3), "amount": round(amount, 2), "status": status})
        return tid

    def link(t: str, account: str, device: str, ip: str, merchant: str) -> None:
        ds.made.append({"account": account, "txn": t})
        ds.on_device.append({"txn": t, "device": device})
        ds.from_ip.append({"txn": t, "ip": ip})
        ds.at.append({"txn": t, "merchant": merchant})

    normal_ips = [d["name"] for d in ds.ips[:40]]
    ring_members = set(RING_A) | set(RING_B)
    noise_devices = [f"D-{260 + i}" for i in range(5)]  # used only by ring-A noise txns

    # innocent regulars: own device, own IP, normal history
    ri = 0
    for a in sorted(all_regular):
        if a in ring_members:
            continue
        dev = f"D-{100 + ri:03d}"  # unique per account
        ri += 1
        ip = rng.choice(normal_ips)
        for _ in range(rng.randint(5, 18)):
            t = rng.uniform(0, 89)
            kind = rng.random()
            amount = rng.uniform(3, 40) if kind < 0.5 else rng.uniform(40, 120) if kind < 0.9 else rng.uniform(120, 400)
            status = "FAILED" if rng.random() < 0.02 else "COMPLETED"
            link(txn(t, amount, status), a, dev, ip, rng.choice(ds.merchants)["name"])

    # ---------------------------------------------------------------- RING A
    base_a = 30.0
    for i, a in enumerate(RING_A):
        dev = f"D-{901 + i % 3}"          # D-901..D-903 shared
        ip = "185.220.101.14" if i % 2 == 0 else "185.220.101.15"
        for _ in range(3):
            t = base_a + rng.uniform(0, 1.5)   # 36h burst
            amount = rng.uniform(350, 1400)    # high value
            link(txn(t, amount, "COMPLETED"), a, dev, ip, rng.choice(ring_a_merchants))
        # a bit of older noise on spare devices so the profile doesn't look empty
        for _ in range(rng.randint(1, 3)):
            t = rng.uniform(0, base_a - 1)
            link(txn(t, rng.uniform(10, 90), "COMPLETED"), a, rng.choice(noise_devices),
                 rng.choice(normal_ips), rng.choice(ds.merchants)["name"])

    # funding: external seeder -> ring -> mules -> external exits
    for i, a in enumerate(RING_A):
        ds.funds.append({"from": "E-9001", "to": a, "amount": round(rng.uniform(500, 900), 2), "time": round(base_a - 0.5, 3)})
    for i, a in enumerate(RING_A):
        mule = MULES[i % len(MULES)]
        ds.funds.append({"from": a, "to": mule, "amount": round(rng.uniform(150, 600), 2), "time": round(base_a + 0.6, 3)})
    for i, mule in enumerate(MULES):
        exit_acct = "E-9002" if i % 2 == 0 else "E-9003"
        ds.funds.append({"from": mule, "to": exit_acct, "amount": round(rng.uniform(400, 1500), 2), "time": round(base_a + 0.9, 3)})

    # ---------------------------------------------------------------- RING B
    base_b = 40.0
    ring_b_devices = ["D-904", "D-905", "D-906"]
    ring_b_ips = ["91.215.85.6", "91.215.85.7"]
    for i, a in enumerate(RING_B):
        dev = ring_b_devices[i % 3]
        ip = ring_b_ips[i % 2]
        for _ in range(5):
            t = base_b + rng.uniform(0, 0.25)    # 6h window
            link(txn(t, rng.uniform(1, 9), "FAILED"), a, dev, ip,
                 rng.choice([m["name"] for m in card_test_merchants]))
    # the "harvest" — a few successes after the burst
    for a in ["A-1100", "A-1101"]:
        for j in range(2):
            t = base_b + 0.3 + j * 0.2
            link(txn(t, rng.uniform(60, 180), "COMPLETED"), a, ring_b_devices[int(a[-1]) % 3],
                 ring_b_ips[int(a[-1]) % 2], rng.choice([m["name"] for m in card_test_merchants]))

    # harmless family transfers
    for _ in range(8):
        a1, a2 = rng.sample([a for a in all_regular if a not in ring_members], 2)
        ds.funds.append({"from": a1, "to": a2, "amount": round(rng.uniform(20, 200), 2), "time": round(rng.uniform(5, 88), 3)})

    # ---------------------------------------------------------------- knowledge
    ds.policies = [
        {"name": "Card Testing Response", "code": "POL-101",
         "threshold": "5+ failed authorizations from one IP within 1 hour",
         "summary": "If 5+ failed transactions occur from a single IP within one hour, freeze the affected accounts, block the IP at the gateway, and escalate to card-security."},
        {"name": "Device Reuse Review", "code": "POL-102",
         "threshold": "3+ distinct accounts on one device",
         "summary": "When 3+ distinct accounts transact from a single device, open a review. If the accounts also share high-value purchases or funding flows, freeze them and link them into one case."},
        {"name": "Mule Chain Protocol", "code": "POL-103",
         "threshold": "funding chain 2+ hops reaching an external account within 24h",
         "summary": "Follow FUNDS edges up to 3 hops from a reviewed account. If a chain reaches an external account within 24h, freeze the entire chain and file an SAR via the compliance runbook."},
        {"name": "High Value Velocity", "code": "POL-104",
         "threshold": "$3,000+ completed retail spend within 24h",
         "summary": "Flag retail accounts whose completed spend exceeds $3,000 in a 24h window for manual review before any freeze is applied."},
        {"name": "Escalation Gate", "code": "POL-200",
         "threshold": "case risk score >= 70",
         "summary": "Any case with a computed risk score of 70 or above must be escalated to fraud-ops, and every action in the case file must cite the policy that triggered it."},
        {"name": "Customer Communication", "code": "POL-210",
         "threshold": "any account freeze",
         "summary": "Freezing an account triggers a customer notification within 24h; business accounts also notify their relationship manager."},
    ]
    ds.runbooks = [
        {"name": "RB-01 Freeze & Escalate", "steps": "1) freeze account  2) cite triggering policies in case  3) create fraud-ops ticket  4) notify customer per POL-210"},
        {"name": "RB-02 IP Block", "steps": "1) verify IP pattern  2) block at gateway  3) tag related accounts  4) 30-day monitoring"},
        {"name": "RB-03 SAR Filing", "steps": "1) document full funding chain  2) quantify moved value  3) legal review  4) file SAR"},
        {"name": "RB-04 Account Review", "steps": "1) pull 90-day profile  2) compare against segment baseline  3) score  4) record decision"},
    ]
    ds.teams = [{"name": "fraud-ops"}, {"name": "card-security"}, {"name": "compliance"}]
    ds.incidents = [
        {"name": "INC-2026-014", "date": "2026-03-12", "summary": "Device ring of 9 accounts draining electronics merchants; caught by POL-102 review, $41k recovered."},
        {"name": "INC-2026-027", "date": "2026-06-02", "summary": "Card-testing burst targeting travel merchants; blocked via POL-101 + RB-02."},
        {"name": "INC-2026-031", "date": "2026-07-19", "summary": "Mule chain moving $28k to 2 external accounts; SAR filed via POL-103/RB-03."},
    ]
    ds.policy_runbook = [
        {"p": "POL-101", "r": "RB-02"}, {"p": "POL-102", "r": "RB-04"},
        {"p": "POL-103", "r": "RB-03"}, {"p": "POL-200", "r": "RB-01"},
    ]
    ds.policy_team = [
        {"p": "POL-101", "t": "card-security"}, {"p": "POL-102", "t": "fraud-ops"},
        {"p": "POL-103", "t": "compliance"}, {"p": "POL-104", "t": "fraud-ops"},
        {"p": "POL-200", "t": "fraud-ops"}, {"p": "POL-210", "t": "fraud-ops"},
    ]
    ds.incident_policy = [
        {"i": "INC-2026-014", "p": "POL-102"},
        {"i": "INC-2026-027", "p": "POL-101"},
        {"i": "INC-2026-031", "p": "POL-103"},
    ]
    return ds


if __name__ == "__main__":
    d = generate()
    print(d.stats())
    assert any(t["status"] == "FAILED" for t in d.txns)
    # sanity: ring A accounts share devices
    dev_of = {}
    for o in d.on_device:
        pass
    acct_devs: dict[str, set] = {}
    for m, o in zip(d.made, d.on_device):
        acct_devs.setdefault(m["account"], set()).add(o["device"])
    shared = set()
    for a in RING_A:
        shared |= acct_devs.get(a, set())
    print("ring A shared devices:", sorted(x for x in shared if x.startswith("D-9")))
    print("OK")
