"""Deterministic labelled SSH scenarios for comparative evaluation."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    category: str
    label: int
    split: str
    log_text: str


NEGATIVE = {"normal", "occasional_mistakes", "legitimate_automation", "malformed"}
POSITIVE = {"concentrated_brute_force", "password_spraying", "slow_brute_force", "success_after_failures"}


def _line(ts: datetime, pid: int, outcome: str, user: str, ip: str, port: int, publickey=False) -> str:
    stamp = ts.strftime("%b %d %H:%M:%S")
    if outcome == "success":
        method = "publickey" if publickey else "password"
        body = f"Accepted {method} for {user} from {ip} port {port} ssh2"
    elif outcome == "invalid":
        body = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    else:
        body = f"Failed password for {user} from {ip} port {port} ssh2"
    return f"{stamp} server sshd[{pid}]: {body}"


def _scenario(category: str, index: int, rng: random.Random) -> str:
    base = datetime(2026, 6, 10, 8, 0, 0) + timedelta(minutes=index * 7)
    ip = f"10.{index // 250}.{(index * 7) % 250}.{10 + index % 200}"
    users = ["alice", "deploy", "backup", "admin", "root", "ubuntu", "git"]
    lines: List[str] = []

    if category == "normal":
        for n in range(rng.randint(3, 7)):
            lines.append(_line(base + timedelta(minutes=n * 8), 1000+n, "success", users[n % 3], ip, 42000+n, publickey=n % 2 == 0))
    elif category == "occasional_mistakes":
        failures = rng.randint(1, 2)
        for n in range(failures):
            lines.append(_line(base + timedelta(minutes=n * 3), 1100+n, "failure", "alice", ip, 43000+n))
        lines.append(_line(base + timedelta(minutes=10), 1199, "success", "alice", ip, 43100))
    elif category == "concentrated_brute_force":
        for n in range(rng.randint(12, 24)):
            lines.append(_line(base + timedelta(seconds=n * rng.randint(3, 8)), 1200+n, "failure", users[n % 6], ip, 44000+n))
    elif category == "password_spraying":
        for n in range(rng.randint(7, 12)):
            lines.append(_line(base + timedelta(seconds=n * 18), 1300+n, "invalid", users[n % len(users)], ip, 45000+n))
    elif category == "slow_brute_force":
        for n in range(rng.randint(5, 9)):
            lines.append(_line(base + timedelta(minutes=n * rng.randint(8, 14)), 1400+n, "failure", users[n % 2], ip, 46000+n))
    elif category == "success_after_failures":
        for n in range(rng.randint(7, 12)):
            lines.append(_line(base + timedelta(seconds=n * 20), 1500+n, "failure", "root", ip, 47000+n))
        lines.append(_line(base + timedelta(minutes=5), 1599, "success", "root", ip, 47100))
    elif category == "legitimate_automation":
        for n in range(rng.randint(12, 22)):
            lines.append(_line(base + timedelta(seconds=n * 6), 1600+n, "success", "backup", ip, 48000+n, publickey=True))
    elif category == "malformed":
        lines = [
            f"{base:%b %d %H:%M:%S} server sshd[1700]: connection reset",
            "not an ssh log",
            f"{base:%b %d %H:%M:%S} server sshd[1701]: Failed password for root from 999.1.1.1 port bad",
        ]
    else:
        raise KeyError(category)
    return "\n".join(lines)


def generate_scenarios(per_category: int = 10, seed: int = 3070) -> List[Scenario]:
    """Generate 80 scenarios by default with a fixed, documented seed."""
    rng = random.Random(seed)
    rows: List[Scenario] = []
    categories = sorted(NEGATIVE | POSITIVE)
    for category in categories:
        for index in range(per_category):
            # Twenty-four normal observations (8 from each suitable category)
            # form the model reference set; all remaining rows are held out.
            split = "train_normal" if category in {"normal", "occasional_mistakes", "legitimate_automation"} and index < 8 else "test"
            rows.append(
                Scenario(
                    scenario_id=f"{category}-{index+1:02d}",
                    category=category,
                    label=1 if category in POSITIVE else 0,
                    split=split,
                    log_text=_scenario(category, index, rng),
                )
            )
    return rows
