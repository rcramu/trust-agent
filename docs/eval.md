# Evaluation harness

Companion deposit for **TrustAgent**. Every number that will appear in manuscript Section 8 / Tables 6–10 / Table A.1 must come from JSON written by this harness. Do not edit result cells by hand.

**Data folder:** [`evaluation/results/`](../evaluation/results/)

## Run

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/python evaluation/run.py --repeats 300
.venv/bin/python evaluation/make_figures.py
```

`--repeats` is the number of independent lab worlds per scenario × baseline. Default 300. The process generates a fresh P-256 key set for every trial. Host, schema, and RSS are recorded in the JSON `host` object (manuscript Appendix B).

Output: `evaluation/results/approach_comparison.json` (`schema: trustagent-eval-v1`).

## Baselines

| ID | Implementation |
|---|---|
| B1 | `EnforcementMode.B1` — no checks |
| B2 | JWT only (`LabIdentityProvider.decode`) |
| B3 | `TrustAgentGateway` full path |

A2A fixtures always carry a compact JWS Agent Card. MCP fixtures carry an audience-bound access token for `mcp://enterprise/tools`.

## Scenarios

| ID | Fixture | What B3 must do |
|---|---|---|
| A1 | Card signed by an unregistered key, valid token for the claimed agent | Deny (P1) |
| A2 | Card signed by the real agent but declaring extra capabilities | Deny (registry compare) |
| A3 | Card payload altered after signing | Deny (JWS) |
| A4 | Access token with `exp` in the past | Deny (B2 also denies) |
| A5 | Unexpired token after registry revoke | Deny (P4); B2 allows |
| A6 | `incident.delete` with a valid security-agent token | Deny (P2); B2 allows |
| A7 | `database.admin` | Deny (P2); B2 allows |
| A8 | Security-agent delegates `incident.delete` (not in its scope) to helper | Deny (P3); B2 allows |
| A9 | Same `jti` presented twice | Deny the second use; B2 allows |
| A10 | In-scope `threat.search` with `behavior_deviation=1.0` | No autonomous allow (ATS); B2 allows |

Legitimate controls L1 (MCP `incident.read`) and L2 (A2A with an honest card) measure false positives.

## Metrics in the JSON

- `scenarios.A*.B*.prevention_rate` — fraction of trials that were not autonomously permitted
- `summary.B*.authorization_quality` — precision / recall / F1 treating “should block” as the positive class (A1–A10 positive, L1–L2 negative)
- `summary.B*.latency` — mean / median / stdev / p95 / p99 over all authorize() calls for that baseline
- `summary.B*.phases` — token, Agent Card, policy, and ATS phase times when that path ran
- `host` — platform, Python, CPU seconds, peak RSS
- `ablation.A10` — B3 vs B3_STATIC vs B3_NO_BEHAVIOR vs B3_NO_RESOURCE (hypothesis H5)

## Mapping to the manuscript

| Manuscript table | JSON path |
|---|---|
| Table 6 | `tables.table6` |
| Table 7 | `tables.table7` |
| Table 8 | `summary.*.authorization_quality` |
| Table 9 | `ablation.A10` |
| Table 10 | `tests` plus the supported/not wording in Section 8.5 |
| Table A.1 | `scenarios` and `legitimate` |
| Fisher tests (H1–H5) | `tests` |
| Figure 6 | `evaluation/make_figures.py` → `figures/figure-06-prevention.png` |
| Figure 7 | `evaluation/make_figures.py` → `figures/figure-07-latency.png` |

## Known limitations

- In-process lab, not a multi-host mesh and not TLS 1.3 on the wire.
- ATS behavior is a policy function over declared purpose plus an explicit `behavior_deviation` fixture, not a learned anomaly model.
- A4 does not distinguish B2 from B3 (both reject expired JWTs). That is expected.
- Replay detection is a process-local `jti` set.
