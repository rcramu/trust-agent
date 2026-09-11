from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.scenarios import LEGITIMATE, SCENARIOS
from trustagent.gateway import EnforcementMode
from trustagent.lab import LabWorld
from trustagent.models import AuthorizationRequest, Decision

MODES = (
    EnforcementMode.B1,
    EnforcementMode.B2,
    EnforcementMode.B3,
)
ABLATION_MODES = (
    EnforcementMode.B3,
    EnforcementMode.B3_STATIC,
    EnforcementMode.B3_NO_BEHAVIOR,
    EnforcementMode.B3_NO_RESOURCE,
)


def _decide(mode: EnforcementMode, request_builder) -> Decision:
    lab = LabWorld()
    gateway = lab.gateway(mode)
    request: AuthorizationRequest = request_builder(lab)
    if request.replay_of:
        first = AuthorizationRequest(
            agent_id=request.agent_id,
            resource=request.resource,
            capability=request.capability,
            token=request.token,
            channel=request.channel,
            audience=request.audience,
        )
        gateway.authorize(first)
    return gateway.authorize(request)


def _rates(allowed: int, n: int) -> dict[str, float | int]:
    success = allowed / n if n else 0.0
    return {
        "n": n,
        "allowed": allowed,
        "denied": n - allowed,
        "attack_success_rate": success,
        "prevention_rate": 1.0 - success,
    }


def _latency_block(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    if not ordered:
        return {}
    p95_idx = max(0, int(round(0.95 * (len(ordered) - 1))))
    p99_idx = max(0, int(round(0.99 * (len(ordered) - 1))))
    return {
        "mean_ms": statistics.fmean(ordered),
        "median_ms": statistics.median(ordered),
        "stdev_ms": statistics.pstdev(ordered) if len(ordered) > 1 else 0.0,
        "p95_ms": ordered[p95_idx],
        "p99_ms": ordered[p99_idx],
    }


def _log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_one_sided(allowed_ctrl: int, denied_ctrl: int, allowed_tx: int, denied_tx: int) -> float:
    """One-sided Fisher's exact: P(treatment allows this many or fewer attacks)."""
    a, b, c, d = allowed_ctrl, denied_ctrl, allowed_tx, denied_tx
    n = a + b + c + d
    row1 = a + b
    row2 = c + d
    col1 = a + c
    lo = max(0, col1 - row1)
    log_den = _log_comb(n, col1)
    total = 0.0
    for k in range(lo, c + 1):
        log_p = _log_comb(row2, k) + _log_comb(row1, col1 - k) - log_den
        total += math.exp(log_p)
    return min(1.0, total)


def _counts(block: dict, *ids: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for mode in ("B1", "B2", "B3"):
        allowed = sum(int(block[sid][mode]["allowed"]) for sid in ids)
        n = sum(int(block[sid][mode]["n"]) for sid in ids)
        out[mode] = {"allowed": allowed, "denied": n - allowed, "n": n}
    return out


def _confusion(true_attack: list[bool], predicted_block: list[bool]) -> dict[str, float]:
    tp = sum(1 for t, p in zip(true_attack, predicted_block, strict=True) if t and p)
    fp = sum(1 for t, p in zip(true_attack, predicted_block, strict=True) if (not t) and p)
    fn = sum(1 for t, p in zip(true_attack, predicted_block, strict=True) if t and (not p))
    tn = sum(1 for t, p in zip(true_attack, predicted_block, strict=True) if (not t) and (not p))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_campaign(repeats: int) -> dict:
    scenarios: dict[str, dict] = {}
    labels: list[bool] = []
    blocked: dict[str, list[bool]] = defaultdict(list)
    latencies: dict[str, list[float]] = defaultdict(list)

    for sid, builder in SCENARIOS.items():
        scenarios[sid] = {}
        for mode in MODES:
            allowed = 0
            samples: list[float] = []
            for _ in range(repeats):
                decision = _decide(mode, builder)
                samples.append(decision.latency_ms)
                latencies[mode.value].append(decision.latency_ms)
                permitted = decision.autonomously_permitted
                if permitted:
                    allowed += 1
                blocked[mode.value].append(not permitted)
                if mode is EnforcementMode.B1:
                    labels.append(True)
            scenarios[sid][mode.value] = {
                **_rates(allowed, repeats),
                "latency": _latency_block(samples),
            }

    legitimate: dict[str, dict] = {}
    for lid, builder in LEGITIMATE.items():
        legitimate[lid] = {}
        for mode in MODES:
            allowed = 0
            samples = []
            for _ in range(repeats):
                decision = _decide(mode, builder)
                samples.append(decision.latency_ms)
                latencies[mode.value].append(decision.latency_ms)
                if decision.autonomously_permitted:
                    allowed += 1
                blocked[mode.value].append(not decision.autonomously_permitted)
                if mode is EnforcementMode.B1:
                    labels.append(False)
            legitimate[lid][mode.value] = {
                "n": repeats,
                "allowed": allowed,
                "denied": repeats - allowed,
                "false_positive_rate": (repeats - allowed) / repeats,
                "latency": _latency_block(samples),
            }

    summary = {}
    for mode in MODES:
        name = mode.value
        attack_rows = [row[name] for row in scenarios.values()]
        prevention = statistics.fmean(r["prevention_rate"] for r in attack_rows)
        success = statistics.fmean(r["attack_success_rate"] for r in attack_rows)
        summary[name] = {
            "mean_prevention_rate": prevention,
            "mean_attack_success_rate": success,
            "authorization_quality": _confusion(labels, blocked[name]),
            "latency": _latency_block(latencies[name]),
        }

    ablation = {"A10": {}}
    for mode in ABLATION_MODES:
        allowed = 0
        samples = []
        for _ in range(repeats):
            decision = _decide(mode, SCENARIOS["A10"])
            samples.append(decision.latency_ms)
            if decision.autonomously_permitted:
                allowed += 1
        ablation["A10"][mode.value] = {
            **_rates(allowed, repeats),
            "latency": _latency_block(samples),
        }

    identity = _counts(scenarios, "A1", "A2", "A3")
    privilege = _counts(scenarios, "A6", "A7", "A8")
    token = _counts(scenarios, "A4", "A5", "A9")
    behavior = _counts(scenarios, "A10")
    legit_n = repeats * len(LEGITIMATE)
    false_positives = {
        mode: sum(int(legitimate[lid][mode]["denied"]) for lid in LEGITIMATE)
        for mode in ("B1", "B2", "B3")
    }
    tests = {
        "alpha": 0.05,
        "h1_overall_B2_vs_B3": {
            "allowed_B2": identity["B2"]["allowed"]
            + privilege["B2"]["allowed"]
            + token["B2"]["allowed"]
            + behavior["B2"]["allowed"],
            "denied_B2": identity["B2"]["denied"]
            + privilege["B2"]["denied"]
            + token["B2"]["denied"]
            + behavior["B2"]["denied"],
            "allowed_B3": 0,
            "denied_B3": 0,
        },
        "h2_A8_B2_vs_B3": {
            "p": fisher_one_sided(
                scenarios["A8"]["B2"]["allowed"],
                scenarios["A8"]["B2"]["denied"],
                scenarios["A8"]["B3"]["allowed"],
                scenarios["A8"]["B3"]["denied"],
            )
        },
        "h3_A1A3_B2_vs_B3": {
            "p": fisher_one_sided(
                identity["B2"]["allowed"],
                identity["B2"]["denied"],
                identity["B3"]["allowed"],
                identity["B3"]["denied"],
            )
        },
        "h5_A10_B2_vs_B3": {
            "p": fisher_one_sided(
                scenarios["A10"]["B2"]["allowed"],
                scenarios["A10"]["B2"]["denied"],
                scenarios["A10"]["B3"]["allowed"],
                scenarios["A10"]["B3"]["denied"],
            )
        },
        "h5_A10_B3_vs_static": {
            "p": fisher_one_sided(
                ablation["A10"]["B3_STATIC"]["allowed"],
                ablation["A10"]["B3_STATIC"]["denied"],
                ablation["A10"]["B3"]["allowed"],
                ablation["A10"]["B3"]["denied"],
            )
        },
        "h5_A10_B3_vs_no_behavior": {
            "p": fisher_one_sided(
                ablation["A10"]["B3_NO_BEHAVIOR"]["allowed"],
                ablation["A10"]["B3_NO_BEHAVIOR"]["denied"],
                ablation["A10"]["B3"]["allowed"],
                ablation["A10"]["B3"]["denied"],
            )
        },
    }
    tests["h1_overall_B2_vs_B3"]["p"] = fisher_one_sided(
        tests["h1_overall_B2_vs_B3"]["allowed_B2"],
        tests["h1_overall_B2_vs_B3"]["denied_B2"],
        identity["B3"]["allowed"]
        + privilege["B3"]["allowed"]
        + token["B3"]["allowed"]
        + behavior["B3"]["allowed"],
        identity["B3"]["denied"]
        + privilege["B3"]["denied"]
        + token["B3"]["denied"]
        + behavior["B3"]["denied"],
    )
    tests["h1_overall_B2_vs_B3"]["allowed_B3"] = (
        identity["B3"]["allowed"]
        + privilege["B3"]["allowed"]
        + token["B3"]["allowed"]
        + behavior["B3"]["allowed"]
    )
    tests["h1_overall_B2_vs_B3"]["denied_B3"] = (
        identity["B3"]["denied"]
        + privilege["B3"]["denied"]
        + token["B3"]["denied"]
        + behavior["B3"]["denied"]
    )

    b2_lat = summary["B2"]["latency"]
    b3_lat = summary["B3"]["latency"]

    def _overhead(tx: float, base: float) -> float:
        return ((tx - base) / base) * 100.0 if base else 0.0

    tables = {
        "table6": {
            "identity_A1_A3": identity,
            "privilege_A6_A8": privilege,
            "token_A4_A5_A9": token,
            "behavior_A10": behavior,
            "false_positives_L1_L2": {
                mode: {"denied": false_positives[mode], "n": legit_n}
                for mode in ("B1", "B2", "B3")
            },
        },
        "table7": {
            "median_ms": {"B2": b2_lat["median_ms"], "B3": b3_lat["median_ms"], "overhead_pct": _overhead(b3_lat["median_ms"], b2_lat["median_ms"])},
            "p95_ms": {"B2" : b2_lat["p95_ms"], "B3": b3_lat["p95_ms"], "overhead_pct": _overhead(b3_lat["p95_ms"], b2_lat["p95_ms"])},
            "p99_ms": {"B2": b2_lat["p99_ms"], "B3": b3_lat["p99_ms"], "overhead_pct": _overhead(b3_lat["p99_ms"], b2_lat["p99_ms"])},
            "a2a_path_L2_median_ms": {
                "B2": legitimate["L2"]["B2"]["latency"]["median_ms"],
                "B3": legitimate["L2"]["B3"]["latency"]["median_ms"],
                "overhead_pct": _overhead(
                    legitimate["L2"]["B3"]["latency"]["median_ms"],
                    legitimate["L2"]["B2"]["latency"]["median_ms"],
                ),
            },
            "mcp_path_L1_median_ms": {
                "B2": legitimate["L1"]["B2"]["latency"]["median_ms"],
                "B3": legitimate["L1"]["B3"]["latency"]["median_ms"],
                "overhead_pct": _overhead(
                    legitimate["L1"]["B3"]["latency"]["median_ms"],
                    legitimate["L1"]["B2"]["latency"]["median_ms"],
                ),
            },
        },
    }

    return {
        "schema": "trustagent-eval-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repeats": repeats,
        "baselines": [m.value for m in MODES],
        "scenarios": scenarios,
        "legitimate": legitimate,
        "summary": summary,
        "ablation": ablation,
        "tests": tests,
        "tables": tables,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the TrustAgent evaluation campaign")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "approach_comparison.json",
    )
    args = parser.parse_args(argv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    payload = run_campaign(args.repeats)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    for name, block in payload["summary"].items():
        quality = block["authorization_quality"]
        print(
            f"{name}: prevention={block['mean_prevention_rate']:.3f} "
            f"P={quality['precision']:.3f} R={quality['recall']:.3f} "
            f"F1={quality['f1']:.3f} median_ms={block['latency']['median_ms']:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
