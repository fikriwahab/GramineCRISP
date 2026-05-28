#!/usr/bin/env python3
"""Parse CRISP profile output from gramine logs and compute aggregate stats.

Usage:
    python3 crisp_profile_analysis.py run1.log [run2.log run3.log ...]
    python3 crisp_profile_analysis.py --plot run1.log run2.log

Expects each log to contain [CRISP CSV] lines emitted by crisp_profile_dump()
when sgx.crisp.profile = true in the manifest. Aggregates count and total_us
across runs, recomputes avg_us. Optional --plot saves crisp_profile.png.
"""

import argparse
import sys
from io import StringIO

import pandas as pd

CSV_PREFIX = "[CRISP CSV] "


def extract_csv(log_path):
    """Read log file, return concatenated CSV text from [CRISP CSV] lines."""
    out = []
    with open(log_path) as f:
        for line in f:
            idx = line.find(CSV_PREFIX)
            if idx >= 0:
                out.append(line[idx + len(CSV_PREFIX):])
    return "".join(out)


def load_run(log_path):
    """Parse one log file into a DataFrame, header row included."""
    csv = extract_csv(log_path)
    if not csv:
        raise ValueError("no [CRISP CSV] lines found")
    return pd.read_csv(StringIO(csv))


def aggregate(dfs):
    """Sum count and total_us across runs, recompute avg_us per slot."""
    combined = pd.concat(dfs, ignore_index=True)
    grouped = combined.groupby("slot", sort=False).agg(
        count=("count", "sum"),
        total_us=("total_us", "sum"),
    )
    grouped["avg_us"] = (grouped["total_us"] / grouped["count"].replace(0, 1)).astype(int)
    return grouped.reset_index()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("logs", nargs="+", help="one or more gramine output log files")
    p.add_argument("--plot", action="store_true", help="save bar chart of avg_us per slot to crisp_profile.png")
    p.add_argument("--per-run", action="store_true", help="print each run separately before aggregating")
    args = p.parse_args()

    dfs = []
    for log in args.logs:
        try:
            df = load_run(log)
        except Exception as exc:
            print(f"WARN {log}: {exc}", file=sys.stderr)
            continue
        df["source"] = log
        dfs.append(df)
        if args.per_run:
            print(f"=== {log} ===")
            print(df.to_string(index=False))
            print()

    if not dfs:
        print("no CRISP profile data found in any input log", file=sys.stderr)
        sys.exit(1)

    print("=== aggregate across runs ===")
    agg = aggregate(dfs)
    print(agg.to_string(index=False))

    if args.plot:
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.bar(agg["slot"], agg["avg_us"])
        ax.set_title("CRISP per-slot average latency (us)")
        ax.set_ylabel("avg us")
        ax.set_xlabel("slot")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig("crisp_profile.png", dpi=120)
        print("saved crisp_profile.png")


if __name__ == "__main__":
    main()
