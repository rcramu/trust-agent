# TrustAgent lab prototype

In-process reference implementation of the TrustAgent gateway described in the JSS draft *TrustAgent: A Zero-Trust Identity and Authorization Framework for Agent-to-Agent and Model Context Protocol Systems*.

The object under test is an authorization control plane. The language-model planner is out of process and out of scope. Security-critical decisions are deterministic.

## What is implemented

- Ephemeral P-256 / ES256 keys (generated in memory; never committed)
- Agent registry and NHI status (active / revoked / expired)
- Lab identity provider: audience-bound JWTs and PKCE (S256) authorization-code exchange
- JWS Agent Cards with declared-versus-registered capability comparison
- Capability policy, monotonic delegation, token `jti` replay cache
- Agent Trust Score (ATS) with B3 ablations (static, no behavior, no resource)
- Thin A2A and MCP facades in `trustagent.channels`
- Evaluation campaign A1–A10 against baselines B1 / B2 / B3

## What is not implemented

- A production identity provider or network TLS terminator
- A full MCP or A2A wire server
- X.509 certificates (raw P-256 keys only)
- Any real enterprise connector

## Reproduce

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
# coverage of src/trustagent must stay at or above 90%
.venv/bin/python evaluation/run.py --repeats 30
```

Results: [`evaluation/results/approach_comparison.json`](evaluation/results/approach_comparison.json). Figures 6–7: `python evaluation/make_figures.py`. How to read them: [`docs/eval.md`](docs/eval.md).

## Enforcement modes

| Mode | Checks |
|---|---|
| B1 | None (always allow) |
| B2 | JWT signature, expiry, audience, subject |
| B3 | B2 + registry + Agent Card + capability + delegation + replay + ATS |
| B3_STATIC | B3 without ATS banding |
| B3_NO_BEHAVIOR | B3, ATS with \(w_B = 0\) |
| B3_NO_RESOURCE | B3, ATS with \(w_R = 0\) |

An unauthorized action is counted as prevented when the outcome is `DENY` or `REQUIRE_HUMAN_APPROVAL`.

## Credentials

No passwords, API keys, or private keys are stored in this repository. Lab keys exist only in the process that created them. Do not add `.pem` files or `.env` secrets.
