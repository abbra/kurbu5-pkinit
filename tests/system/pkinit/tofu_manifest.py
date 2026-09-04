#!/usr/bin/env python3
"""Assemble a TOFU report manifest from a directory of scenario results.

Usage:
    tofu_manifest.py REPORTDIR REALM OUTPUT.json

REPORTDIR contains one sub-directory per scenario (processed in sorted order),
each with:

    meta.env   key=value lines: name, title, expected, outcome, broker_mode,
               broker_decision, ca_fingerprint
    steps.txt  one timeline step per line (optional)
    client-trace.log / kdc-trace.log / broker.log  (optional)

The `passed` flag is derived as (outcome == expected). The output JSON matches
the shape consumed by tofu_report.py.
"""

import datetime
import json
import os
import sys

TRACE_FILES = [
    ("Client trace", "client-trace.log"),
    ("KDC trace", "kdc-trace.log"),
    ("Broker log", "broker.log"),
]

META_KEYS = [
    "name",
    "title",
    "expected",
    "outcome",
    "broker_mode",
    "broker_decision",
    "ca_fingerprint",
]


def parse_meta(path):
    meta = {}
    if not os.path.exists(path):
        return meta
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            meta[key.strip()] = value
    return meta


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


def build_scenario(scenario_dir):
    meta = parse_meta(os.path.join(scenario_dir, "meta.env"))
    sc = {k: meta.get(k, "") for k in META_KEYS}
    if not sc["name"]:
        sc["name"] = os.path.basename(scenario_dir)

    steps_text = read_text(os.path.join(scenario_dir, "steps.txt"))
    sc["steps"] = (
        [s for s in steps_text.splitlines() if s.strip()] if steps_text else []
    )

    traces = {}
    for label, fname in TRACE_FILES:
        text = read_text(os.path.join(scenario_dir, fname))
        if text is not None:
            traces[label] = text
    sc["traces"] = traces

    sc["passed"] = sc["expected"] != "" and sc["expected"] == sc["outcome"]
    return sc


def main(argv):
    if len(argv) != 4:
        print(f"usage: {argv[0]} REPORTDIR REALM OUTPUT.json", file=sys.stderr)
        return 2
    reportdir, realm, output = argv[1], argv[2], argv[3]

    scenario_dirs = sorted(
        os.path.join(reportdir, d)
        for d in os.listdir(reportdir)
        if os.path.isdir(os.path.join(reportdir, d))
    )
    scenarios = [build_scenario(d) for d in scenario_dirs]

    manifest = {
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "realm": realm,
        "scenarios": scenarios,
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[tofu-manifest] wrote {output} ({len(scenarios)} scenarios)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
