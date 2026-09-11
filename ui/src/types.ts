export type Mode = "B1" | "B2" | "B3";

export type Cell = {
  n: number;
  allowed: number;
  denied: number;
  attack_success_rate?: number;
  prevention_rate?: number;
  false_positive_rate?: number;
  latency?: Latency;
};

export type Latency = {
  mean_ms: number;
  median_ms: number;
  stdev_ms: number;
  p95_ms: number;
  p99_ms: number;
};

export type Count = {
  allowed?: number;
  denied: number;
  n: number;
};

export type Campaign = {
  schema: string;
  generated_at: string;
  repeats: number;
  host: {
    platform: string;
    python: string;
    cpu_seconds: number;
    max_rss_bytes: number;
  };
  baselines: Mode[];
  scenarios: Record<string, Record<Mode, Cell>>;
  legitimate: Record<string, Record<Mode, Cell>>;
  summary: Record<
    Mode,
    {
      mean_prevention_rate: number;
      mean_attack_success_rate: number;
      authorization_quality: {
        tp: number;
        fp: number;
        fn: number;
        tn: number;
        precision: number;
        recall: number;
        f1: number;
      };
      latency: Latency;
      phases: Record<string, Latency>;
    }
  >;
  ablation: {
    A10: Record<string, Cell>;
  };
  tests: {
    alpha: number;
    h1_overall_B2_vs_B3: {
      allowed_B2: number;
      denied_B2: number;
      allowed_B3: number;
      denied_B3: number;
      p: number;
    };
    h2_A8_B2_vs_B3: { p: number };
    h3_A1A3_B2_vs_B3: { p: number };
    h5_A10_B2_vs_B3: { p: number };
    h5_A10_B3_vs_static: { p: number };
    h5_A10_B3_vs_no_behavior: { p: number };
  };
  tables: {
    table6: {
      identity_A1_A3: Record<Mode, Count>;
      privilege_A6_A8: Record<Mode, Count>;
      token_A4_A5_A9: Record<Mode, Count>;
      behavior_A10: Record<Mode, Count>;
      false_positives_L1_L2: Record<Mode, Count>;
    };
    table7: Record<
      string,
      {
        B2: number;
        B3: number;
        overhead_pct: number;
      }
    >;
  };
};
