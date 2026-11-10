#!/usr/bin/env python3
"""Generate a fresh sample PLC/RTU log dataset (CSV) for OT-Sentinel demos.

Timestamps are always generated relative to "now", so the pledged attack
scenarios stay inside the detection windows:

  * baseline plant-floor traffic (READ/WRITE/LOGIN, mostly SUCCESS)
  * BRUTE_FORCE: 12 failed logins from one IP inside a 60-minute window
  * UNUSUAL_COMMAND: STOP / DELETE bursts from two sources
  * OFF_HOURS_ACTIVITY: a handful of commands at night (00:00-05:00)

Usage:
  python3 scripts/generate_sample_logs.py [output.csv]
"""
import datetime
import random
import sys
from pathlib import Path

BASELINE = 120
IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.20", "10.0.0.5", "10.0.0.99",
       "172.16.0.44", "192.168.1.50", "10.0.0.22", "172.16.0.9", "192.168.1.77"]
COMMANDS = ["READ", "WRITE", "LOGIN"]
DEVICES = ["PLC-01", "PLC-02", "PLC-03", "RTU-01", "RTU-02"]

def fmt(ts: datetime.datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")

def main() -> None:
    random.seed()
    now = datetime.datetime.now()

    rows = []
    # One hour of plausible, mostly-successful baseline traffic.
    base = now - datetime.timedelta(minutes=55)
    for _ in range(BASELINE):
        ts = base + datetime.timedelta(seconds=random.randint(0, 55 * 60))
        status = "FAILURE" if random.random() < 0.10 else "SUCCESS"
        rows.append(f"{fmt(ts)},{random.choice(IPS)},{random.choice(COMMANDS)},{status},{random.choice(DEVICES)}")

    # Brute-force burst: 12 failed logins inside the 60-minute window.
    bf = now - datetime.timedelta(minutes=25)
    for k in range(12):
        rows.append(f"{fmt(bf + datetime.timedelta(seconds=k * 12))},192.168.1.50,LOGIN,FAILURE,PLC-01")

    # Unusual control commands (recent, inside normal hours).
    uc = now - datetime.timedelta(minutes=20)
    for k in range(6):
        rows.append(f"{fmt(uc + datetime.timedelta(seconds=k * 30))},10.0.0.99,STOP,FAILURE,PLC-02")
    for k in range(4):
        rows.append(f"{fmt(uc + datetime.timedelta(minutes=3, seconds=k * 20))},172.16.0.44,DELETE,SUCCESS,PLC-03")

    # Off-hours reconnaissance: early-morning commands (outside brute-force window).
    oh = now.replace(hour=random.choice([1, 2, 3]), minute=0, second=0)
    for k in range(5):
        rows.append(f"{fmt(oh + datetime.timedelta(minutes=k * 9))},10.0.0.77,READ,SUCCESS,RTU-02")

    random.shuffle(rows)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src/main/resources/sample-data/plc_logs.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("timestamp,sourceIp,command,status,deviceId\n" + "\n".join(rows) + "\n")
    print(f"wrote {out} with {len(rows) + 1} lines")

if __name__ == "__main__":
    main()
