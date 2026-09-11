import { useMemo, useState } from "react";
import seeded from "../../evaluation/results/approach_comparison.json";
import type { Campaign, Mode } from "./types";

const MODES: Mode[] = ["B1", "B2", "B3"];
const MODE_LABEL: Record<Mode, string> = {
  B1: "B1 none",
  B2: "B2 JWT",
  B3: "B3 TrustAgent",
};

const SCENARIO_LABEL: Record<string, string> = {
  A1: "Identity spoofing",
  A2: "Card capability inflation",
  A3: "Invalid card signature",
  A4: "Expired credential",
  A5: "Revoked agent",
  A6: "Unauthorized MCP tool",
  A7: "Privilege escalation",
  A8: "Non-monotonic delegation",
  A9: "Token replay",
  A10: "Behavioral deviation",
  L1: "Legitimate MCP incident.read",
  L2: "Legitimate A2A honest card",
};

const TABLE6: { key: keyof Campaign["tables"]["table6"]; label: string }[] = [
  { key: "identity_A1_A3", label: "Identity (A1–A3)" },
  { key: "privilege_A6_A8", label: "Privilege / MCP (A6–A8)" },
  { key: "token_A4_A5_A9", label: "Token / revocation (A4, A5, A9)" },
  { key: "behavior_A10", label: "Behavior (A10)" },
  { key: "false_positives_L1_L2", label: "False positives (L1, L2)" },
];

const TABLE7: { key: string; label: string }[] = [
  { key: "median_ms", label: "Median authorize()" },
  { key: "p95_ms", label: "P95" },
  { key: "p99_ms", label: "P99" },
  { key: "a2a_path_L2_median_ms", label: "A2A path median (L2)" },
  { key: "mcp_path_L1_median_ms", label: "MCP path median (L1)" },
];

const PHASE_LABEL: Record<string, string> = {
  token_ms: "Token",
  card_ms: "Agent Card",
  policy_ms: "Policy",
  ats_ms: "ATS",
};

function fmtP(value: number): string {
  if (value === 0) return "< 1e-300";
  if (value < 0.001) return value.toExponential(2);
  return value.toFixed(3);
}

function fmtMs(value: number): string {
  return `${value.toFixed(3)} ms`;
}

function fmtPct(value: number): string {
  return `${value.toFixed(1)}%`;
}

function fmtBytes(value: number): string {
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function ratio(denied: number, n: number): string {
  return `${denied}/${n}`;
}

export default function App() {
  const [data, setData] = useState<Campaign>(seeded as Campaign);
  const [source, setSource] = useState("evaluation/results/approach_comparison.json");
  const [selected, setSelected] = useState("A1");
  const [error, setError] = useState<string | null>(null);

  const scenarioIds = Object.keys(data.scenarios);
  const legitIds = Object.keys(data.legitimate);
  const quality = data.summary.B3.authorization_quality;
  const table7 = data.tables.table7;

  const selectedCell = useMemo(() => {
    if (selected in data.scenarios) return data.scenarios[selected];
    return data.legitimate[selected];
  }, [data, selected]);

  async function onFile(file: File | undefined) {
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as Campaign;
      if (parsed.schema !== "trustagent-eval-v1") {
        throw new Error("JSON schema is not trustagent-eval-v1");
      }
      setData(parsed);
      setSource(file.name);
      setSelected(Object.keys(parsed.scenarios)[0] ?? "A1");
      setError(null);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Could not read JSON");
    }
  }

  return (
    <div className="page">
      <header className="hero">
        <p className="kicker">Journal of Systems and Software companion</p>
        <h1>TrustAgent lab results</h1>
        <p className="lede">
          In-process evaluation of A1–A10 against B1 / B2 / B3. Cells come from{" "}
          <code>{source}</code>, not from typed tables.
        </p>
        <dl className="meta">
          <div>
            <dt>Generated</dt>
            <dd>{data.generated_at.replace("T", " ").replace(/\+.*/, " UTC")}</dd>
          </div>
          <div>
            <dt>Repeats</dt>
            <dd>{data.repeats} lab worlds / cell</dd>
          </div>
          <div>
            <dt>Host</dt>
            <dd>
              {data.host.python} · {fmtBytes(data.host.max_rss_bytes)} · {data.host.cpu_seconds.toFixed(2)} CPU s
            </dd>
          </div>
        </dl>
        <label className="file">
          Load another campaign JSON
          <input
            type="file"
            accept="application/json,.json"
            onChange={(event) => void onFile(event.target.files?.[0])}
          />
        </label>
        {error ? <p className="error">{error}</p> : null}
      </header>

      <section className="kpis" aria-label="Headline metrics">
        <article>
          <h2>B3 prevention</h2>
          <p className="stat">
            {data.tests.h1_overall_B2_vs_B3.denied_B3}/{data.tests.h1_overall_B2_vs_B3.denied_B3 + data.tests.h1_overall_B2_vs_B3.allowed_B3}
          </p>
          <p className="hint">Unauthorized actions withheld</p>
        </article>
        <article>
          <h2>B2 prevention</h2>
          <p className="stat">
            {data.tests.h1_overall_B2_vs_B3.denied_B2}/{data.tests.h1_overall_B2_vs_B3.denied_B2 + data.tests.h1_overall_B2_vs_B3.allowed_B2}
          </p>
          <p className="hint">Expired tokens only (A4)</p>
        </article>
        <article>
          <h2>B3 F1</h2>
          <p className="stat">{quality.f1.toFixed(2)}</p>
          <p className="hint">
            {quality.tp + quality.fn + quality.tn + quality.fp} labeled requests
          </p>
        </article>
        <article>
          <h2>Median overhead</h2>
          <p className="stat">{fmtPct(table7.median_ms.overhead_pct)}</p>
          <p className="hint">
            {fmtMs(table7.median_ms.B2)} → {fmtMs(table7.median_ms.B3)}
          </p>
        </article>
      </section>

      <section>
        <h2>Table 6. Unauthorized-action prevention</h2>
        <p className="caption">Denied / n. False-positive row is denied legitimate controls.</p>
        <GroupedBars data={data} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                {MODES.map((mode) => (
                  <th key={mode}>{MODE_LABEL[mode]}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TABLE6.map((row) => (
                <tr key={row.key}>
                  <td>{row.label}</td>
                  {MODES.map((mode) => {
                    const cell = data.tables.table6[row.key][mode];
                    return <td key={mode}>{ratio(cell.denied, cell.n)}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Scenarios A1–A10 and controls L1–L2</h2>
        <p className="caption">Select a fixture to see allowed versus denied counts for each baseline.</p>
        <div className="scenario-grid">
          {[...scenarioIds, ...legitIds].map((id) => {
            const block = id in data.scenarios ? data.scenarios[id] : data.legitimate[id];
            const prevented = block.B3.denied === block.B3.n;
            return (
              <button
                key={id}
                type="button"
                className={id === selected ? "chip active" : "chip"}
                onClick={() => setSelected(id)}
              >
                <strong>{id}</strong>
                <span>{SCENARIO_LABEL[id] ?? id}</span>
                <em className={prevented && id.startsWith("A") ? "ok" : ""}>
                  B3 {ratio(block.B3.denied, block.B3.n)}
                </em>
              </button>
            );
          })}
        </div>
        {selectedCell ? (
          <div className="detail">
            <h3>
              {selected} — {SCENARIO_LABEL[selected] ?? selected}
            </h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Mode</th>
                    <th>Allowed</th>
                    <th>Denied</th>
                    <th>Prevention</th>
                    <th>Median latency</th>
                  </tr>
                </thead>
                <tbody>
                  {MODES.map((mode) => {
                    const cell = selectedCell[mode];
                    const prevention = cell.n ? cell.denied / cell.n : 0;
                    return (
                      <tr key={mode}>
                        <td>{MODE_LABEL[mode]}</td>
                        <td>{cell.allowed}</td>
                        <td>{cell.denied}</td>
                        <td>{fmtPct(prevention * 100)}</td>
                        <td>{cell.latency ? fmtMs(cell.latency.median_ms) : "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
      </section>

      <section>
        <h2>Authorization quality</h2>
        <p className="caption">Positive class = unauthorized fixture that should be blocked.</p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Mode</th>
                <th>TP</th>
                <th>FP</th>
                <th>FN</th>
                <th>TN</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
              </tr>
            </thead>
            <tbody>
              {MODES.map((mode) => {
                const q = data.summary[mode].authorization_quality;
                return (
                  <tr key={mode}>
                    <td>{MODE_LABEL[mode]}</td>
                    <td>{q.tp}</td>
                    <td>{q.fp}</td>
                    <td>{q.fn}</td>
                    <td>{q.tn}</td>
                    <td>{q.precision.toFixed(2)}</td>
                    <td>{q.recall.toFixed(2)}</td>
                    <td>{q.f1.toFixed(2)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Table 7. In-process authorization latency</h2>
        <p className="caption">Not a network or TLS measurement. Overhead is (B3 − B2) / B2.</p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th>B2</th>
                <th>B3</th>
                <th>Overhead</th>
              </tr>
            </thead>
            <tbody>
              {TABLE7.map((row) => {
                const cell = table7[row.key];
                return (
                  <tr key={row.key}>
                    <td>{row.label}</td>
                    <td>{fmtMs(cell.B2)}</td>
                    <td>{fmtMs(cell.B3)}</td>
                    <td>{fmtPct(cell.overhead_pct)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <h3>B3 phase medians</h3>
        <ul className="phases">
          {Object.entries(data.summary.B3.phases).map(([name, block]) => (
            <li key={name}>
              <span>{PHASE_LABEL[name] ?? name}</span>
              <strong>{fmtMs(block.median_ms)}</strong>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>A10 ATS ablation (H5)</h2>
        <p className="caption">In-scope threat.search with behavior_deviation=1.0. Static and no-behavior modes must not get credit for P2.</p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Mode</th>
                <th>Allowed</th>
                <th>Denied</th>
                <th>Prevention</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.ablation.A10).map(([mode, cell]) => (
                <tr key={mode}>
                  <td>{mode}</td>
                  <td>{cell.allowed}</td>
                  <td>{cell.denied}</td>
                  <td>{fmtPct(cell.prevention_rate * 100)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Hypotheses</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Test</th>
                <th>One-sided Fisher p</th>
                <th>α</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>H1 overall B2 vs B3</td>
                <td>{fmtP(data.tests.h1_overall_B2_vs_B3.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
              <tr>
                <td>H2 A8 B2 vs B3</td>
                <td>{fmtP(data.tests.h2_A8_B2_vs_B3.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
              <tr>
                <td>H3 A1–A3 B2 vs B3</td>
                <td>{fmtP(data.tests.h3_A1A3_B2_vs_B3.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
              <tr>
                <td>H5 A10 B2 vs B3</td>
                <td>{fmtP(data.tests.h5_A10_B2_vs_B3.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
              <tr>
                <td>H5 A10 vs static</td>
                <td>{fmtP(data.tests.h5_A10_B3_vs_static.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
              <tr>
                <td>H5 A10 vs no-behavior</td>
                <td>{fmtP(data.tests.h5_A10_B3_vs_no_behavior.p)}</td>
                <td>{data.tests.alpha}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function GroupedBars({ data }: { data: Campaign }) {
  const groups = TABLE6.filter((row) => row.key !== "false_positives_L1_L2");
  const width = 720;
  const height = 220;
  const pad = { top: 16, right: 16, bottom: 36, left: 36 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const groupW = innerW / groups.length;
  const barW = groupW / (MODES.length + 1);

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Prevention rate by threat group">
      <text x={pad.left} y={12} className="axis">
        Prevention rate
      </text>
      {[0, 0.5, 1].map((tick) => {
        const y = pad.top + innerH * (1 - tick);
        return (
          <g key={tick}>
            <line x1={pad.left} x2={width - pad.right} y1={y} y2={y} className="grid" />
            <text x={pad.left - 6} y={y + 3} className="axis" textAnchor="end">
              {tick.toFixed(1)}
            </text>
          </g>
        );
      })}
      {groups.map((group, gi) => {
        const gx = pad.left + gi * groupW;
        return (
          <g key={group.key}>
            {MODES.map((mode, mi) => {
              const cell = data.tables.table6[group.key][mode];
              const rate = cell.n ? cell.denied / cell.n : 0;
              const h = innerH * rate;
              return (
                <rect
                  key={mode}
                  className={`bar bar-${mode.toLowerCase()}`}
                  x={gx + barW * (mi + 0.5)}
                  y={pad.top + innerH - h}
                  width={barW * 0.9}
                  height={h}
                />
              );
            })}
            <text x={gx + groupW / 2} y={height - 8} className="axis" textAnchor="middle">
              {group.label.replace(" / MCP", "").replace(" / revocation", "")}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
