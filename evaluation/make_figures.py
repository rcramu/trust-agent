"""Render manuscript Figures 6 and 7 from approach_comparison.json. Not generative AI."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evaluation" / "results" / "approach_comparison.json"
OUT = ROOT / "figures"
MODES = ("B1", "B2", "B3")
LABELS = {"B1": "B1 none", "B2": "B2 JWT", "B3": "B3 TrustAgent"}
COLORS = {"B1": "#9aa0a6", "B2": "#5f7c8a", "B3": "#1b4d6e"}


def _prevention(data: dict, ids: tuple[str, ...], mode: str) -> float:
    denied = sum(data["scenarios"][sid][mode]["denied"] for sid in ids)
    n = sum(data["scenarios"][sid][mode]["n"] for sid in ids)
    return denied / n


def figure6(data: dict) -> None:
    groups = [
        ("A1–A3 identity", ("A1", "A2", "A3")),
        ("A6–A8 privilege", ("A6", "A7", "A8")),
        ("A4/A5/A9 token", ("A4", "A5", "A9")),
        ("A10 behavior", ("A10",)),
    ]
    x = range(len(groups))
    width = 0.25
    fig, ax = plt.subplots(figsize=(8.2, 4.2))
    for i, mode in enumerate(MODES):
        xs = [xi + (i - 1) * width for xi in x]
        ys = [_prevention(data, ids, mode) for _, ids in groups]
        ax.bar(xs, ys, width=width, label=LABELS[mode], color=COLORS[mode])
    ax.set_xticks(list(x))
    ax.set_xticklabels([name for name, _ in groups])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Prevention rate")
    ax.set_title("Figure 6. Unauthorized-action prevention (n=30 per scenario)")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "figure-06-prevention.png", dpi=200)
    plt.close(fig)


def figure7(data: dict) -> None:
    lat = {mode: data["summary"][mode]["latency"] for mode in ("B2", "B3")}
    metrics = [("median", "median_ms"), ("p95", "p95_ms"), ("p99", "p99_ms")]
    x = range(len(metrics))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    for i, mode in enumerate(("B2", "B3")):
        xs = [xi + (i - 0.5) * width for xi in x]
        ys = [lat[mode][key] for _, key in metrics]
        ax.bar(xs, ys, width=width, label=LABELS[mode], color=COLORS[mode])
    ax.set_xticks(list(x))
    ax.set_xticklabels([name for name, _ in metrics])
    ax.set_ylabel("authorize() latency (ms)")
    ax.set_title("Figure 7. In-process authorization latency")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "figure-07-latency.png", dpi=200)
    plt.close(fig)


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True, exist_ok=True)
    figure6(data)
    figure7(data)
    print(f"wrote {OUT / 'figure-06-prevention.png'}")
    print(f"wrote {OUT / 'figure-07-latency.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
