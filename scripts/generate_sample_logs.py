#!/usr/bin/env python3
"""Generate fresh sample datasets for OT-Sentinel demos.

Produces BOTH ingestion formats with timestamps relative to "now", so the
planted attack scenarios always stay inside the detection windows:

  1. src/main/resources/sample-data/plc_logs.csv      (canonical CSV)
  2. src/main/resources/sample-data/raw_plc_logs.txt  (proprietary PLC text)

Attack scenarios planted in both:
  * BRUTE_FORCE       : 12 failed logins from one IP inside a 60-minute window
  * UNUSUAL_COMMAND   : STOP / SHUTDOWN / DELETE / RESET bursts from two sources
  * OFF_HOURS_ACTIVITY: several commands at night (00:00-05:59)

Usage:
  python3 scripts/generate_sample_logs.py
"""
import datetime
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "src/main/resources/sample-data"

BASELINE = 120
IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.20", "10.0.0.5", "10.0.0.99",
       "172.16.0.44", "192.168.1.50", "10.0.0.22", "172.16.0.9", "192.168.1.77"]
COMMANDS = ["READ", "WRITE", "LOGIN"]
DEVICES = ["PLC-01", "PLC-02", "PLC-03", "RTU-01", "RTU-02", "HMI-CONTROL-03"]

# Public resolvers the plant talks to. Their ranges are in the IP location
# register, so the threat map can show a verified public location for them.
PUBLIC_IPS = ["8.8.4.210", "8.8.8.210", "1.1.1.44", "9.9.9.44"]


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def build_rows():
    """Return a list of (timestamp, device, ip, command, status) tuples."""
    random.seed()
    now = datetime.datetime.now()
    rows = []

    # One hour of plausible, mostly-successful baseline traffic.
    base = now - datetime.timedelta(minutes=55)
    for _ in range(BASELINE):
        ts = base + datetime.timedelta(seconds=random.randint(0, 55 * 60))
        status = "FAIL" if random.random() < 0.10 else "OK"
        rows.append((ts, random.choice(DEVICES), random.choice(IPS),
                     random.choice(COMMANDS), status))

    # A little external egress: the plant resolving names through public DNS.
    egress = now - datetime.timedelta(minutes=40)
    for k in range(8):
        rows.append((egress + datetime.timedelta(seconds=k * 90), "RTU-01",
                     PUBLIC_IPS[k % len(PUBLIC_IPS)], "READ", "OK"))

    # Brute-force burst: 12 failed logins inside the 60-minute window.
    bf = now - datetime.timedelta(minutes=25)
    for k in range(12):
        rows.append((bf + datetime.timedelta(seconds=k * 12), "HMI-CONTROL-03",
                     "192.168.1.50", "LOGIN", "FAIL"))

    # Unusual control commands (recent, inside normal hours).
    uc = now - datetime.timedelta(minutes=20)
    for k in range(6):
        rows.append((uc + datetime.timedelta(seconds=k * 30), "PLC-02",
                     "10.0.0.99", random.choice(["STOP", "STOP", "SHUTDOWN"]), "DENIED"))
    for k in range(4):
        rows.append((uc + datetime.timedelta(minutes=3, seconds=k * 20), "PLC-03",
                     "172.16.0.44", "DELETE", "OK"))

    # Off-hours reconnaissance: early-morning commands (outside brute-force window).
    oh = now.replace(hour=random.choice([1, 2, 3]), minute=0, second=0)
    for k in range(5):
        rows.append((oh + datetime.timedelta(minutes=k * 9), "RTU-02",
                     "10.0.0.77", "READ", "OK"))

    random.shuffle(rows)
    return rows


def canon_status(s: str) -> str:
    """Canonical CSV vocabulary - the detection rules match on SUCCESS/FAILURE exactly."""
    return {"OK": "SUCCESS", "FAIL": "FAILURE", "DENIED": "FAILURE"}.get(s, s.upper())


def write_csv(rows: list, out: Path):
    lines = ["timestamp,sourceIp,command,status,deviceId"]
    for ts, device, ip, cmd, status in rows:
        lines.append(f"{fmt(ts)},{ip},{cmd},{canon_status(status)},{device}")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(rows)} rows)")


def write_raw(rows: list, out: Path):
    lines = []
    for ts, device, ip, cmd, status in rows:
        level = "INFO" if status == "OK" else "WARN"
        lines.append(f"[{fmt(ts)}] {level} Device={device} Source={ip} Action={cmd} Result={status}")
    # A couple of realistic noise lines the normaliser must skip.
    lines.insert(0, "PLC LOG DUMP - device HMI-CONTROL-03 - firmware 4.2.1")
    lines.append(">>> export finished, 1 line deliberately malformed <<<")
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(lines)} lines)")


def main():
    rows = build_rows()
    SAMPLES.mkdir(parents=True, exist_ok=True)
    write_csv(rows, SAMPLES / "plc_logs.csv")
    write_raw(rows, SAMPLES / "raw_plc_logs.txt")


if __name__ == "__main__":
    main()
