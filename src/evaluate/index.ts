import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const BASE_URL = process.argv.includes("--base-url")
  ? process.argv[process.argv.indexOf("--base-url") + 1]
  : "http://localhost:8080";

const GOOD_FILE = process.argv.includes("--good-file")
  ? process.argv[process.argv.indexOf("--good-file") + 1]
  : "testing-data/payloads-good.txt";

const BAD_FILE = process.argv.includes("--bad-file")
  ? process.argv[process.argv.indexOf("--bad-file") + 1]
  : "testing-data/payloads-bad.txt";

const OUTPUT_CSV = "testing-data/evaluation_results.csv";
const OUTPUT_JSON = "testing-data/evaluation_summary.json";
const OUTPUT_MD = "testing-data/evaluation_report.md";

interface TestRow {
  payload: string;
  label: "good" | "bad";
  statusCode: number;
  blocked: boolean;
  rateLimited: boolean;
  latencyMs: number;
}

function readPayloads(path: string): string[] {
  return readFileSync(path, "utf-8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

async function runCase(payload: string, label: "good" | "bad"): Promise<TestRow> {
  const url = `${BASE_URL.replace(/\/$/, "")}/search?q=${encodeURIComponent(payload)}`;
  const start = performance.now();
  const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
  const latencyMs = Math.round((performance.now() - start) * 100) / 100;
  return {
    payload,
    label,
    statusCode: res.status,
    blocked: res.status === 403 || res.status === 429,
    rateLimited: res.status === 429,
    latencyMs,
  };
}

function computeMetrics(rows: TestRow[]) {
  const evaluated = rows.filter((r) => !r.rateLimited);
  const rateLimitedCount = rows.length - evaluated.length;

  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (const r of evaluated) {
    if (r.label === "bad" && r.blocked) tp++;
    else if (r.label === "good" && !r.blocked) tn++;
    else if (r.label === "good" && r.blocked) fp++;
    else if (r.label === "bad" && !r.blocked) fn++;
  }
  const total = evaluated.length;
  const accuracy = total ? (tp + tn) / total : 0;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const avgLatency = rows.length ? rows.reduce((s, r) => s + r.latencyMs, 0) / rows.length : 0;

  return {
    totalSent: rows.length,
    totalEvaluated: total,
    rateLimited: rateLimitedCount,
    tp, tn, fp, fn,
    accuracy: Math.round(accuracy * 10000) / 10000,
    precision: Math.round(precision * 10000) / 10000,
    recall: Math.round(recall * 10000) / 10000,
    f1Score: Math.round(f1 * 10000) / 10000,
    avgLatencyMs: Math.round(avgLatency * 100) / 100,
  };
}

function writeCSV(rows: TestRow[]) {
  const header = "payload,label,status_code,blocked,rate_limited,latency_ms";
  const lines = rows.map(
    (r) => `"${r.payload.replace(/"/g, '""')}",${r.label},${r.statusCode},${r.blocked},${r.rateLimited},${r.latencyMs}`,
  );
  ensureDir(OUTPUT_CSV);
  writeFileSync(OUTPUT_CSV, [header, ...lines].join("\n"), "utf-8");
}

function writeJSON(summary: ReturnType<typeof computeMetrics>) {
  ensureDir(OUTPUT_JSON);
  writeFileSync(OUTPUT_JSON, JSON.stringify(summary, null, 2), "utf-8");
}

function writeMD(summary: ReturnType<typeof computeMetrics>) {
  const lines = [
    "# WAF Evaluation Report",
    "",
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total sent | ${summary.totalSent} |`,
    `| Rate limited (excluded) | ${summary.rateLimited} |`,
    `| Evaluated | ${summary.totalEvaluated} |`,
    `| True Positives (TP) | ${summary.tp} |`,
    `| True Negatives (TN) | ${summary.tn} |`,
    `| False Positives (FP) | ${summary.fp} |`,
    `| False Negatives (FN) | ${summary.fn} |`,
    `| Accuracy | ${summary.accuracy} |`,
    `| Precision | ${summary.precision} |`,
    `| Recall | ${summary.recall} |`,
    `| F1 Score | ${summary.f1Score} |`,
    `| Avg Latency (ms) | ${summary.avgLatencyMs} |`,
    "",
    "## Formulas",
    "",
    "- Accuracy = (TP + TN) / Evaluated",
    "- Precision = TP / (TP + FP)",
    "- Recall = TP / (TP + FN)",
    "- F1 = 2 * Precision * Recall / (Precision + Recall)",
    "",
    "Rate-limited requests (HTTP 429) are excluded from the confusion matrix",
    "because they test the rate limiter, not the scoring engine.",
  ];
  ensureDir(OUTPUT_MD);
  writeFileSync(OUTPUT_MD, lines.join("\n"), "utf-8");
}

function ensureDir(filePath: string) {
  mkdirSync(dirname(filePath), { recursive: true });
}

async function main() {
  console.log(`\nWAF Evaluation Runner`);
  console.log(`Target: ${BASE_URL}\n`);

  const goodPayloads = readPayloads(GOOD_FILE);
  const badPayloads = readPayloads(BAD_FILE);
  console.log(`Loaded ${goodPayloads.length} good + ${badPayloads.length} bad payloads\n`);

  const rows: TestRow[] = [];

  for (const p of goodPayloads) {
    const row = await runCase(p, "good");
    rows.push(row);
    const mark = row.rateLimited ? "RL " : row.blocked ? "FP!" : " OK";
    console.log(`  [${mark}] good: ${p.substring(0, 50)}`);
  }

  for (const p of badPayloads) {
    const row = await runCase(p, "bad");
    rows.push(row);
    const mark = row.rateLimited ? "RL " : row.blocked ? " OK" : "FN!";
    console.log(`  [${mark}]  bad: ${p.substring(0, 50)}`);
  }

  const summary = computeMetrics(rows);

  writeCSV(rows);
  writeJSON(summary);
  writeMD(summary);

  console.log(`\n--- Results ---`);
  console.log(`  Sent: ${summary.totalSent}  Evaluated: ${summary.totalEvaluated}  Rate limited: ${summary.rateLimited}`);
  if (summary.rateLimited > 0) {
    console.log(`  (!) ${summary.rateLimited} requests were rate-limited and excluded from accuracy metrics.`);
    console.log(`      Wait 60s or restart the WAF before re-running for clean results.`);
  }
  console.log(`  TP: ${summary.tp}  TN: ${summary.tn}  FP: ${summary.fp}  FN: ${summary.fn}`);
  console.log(`  Accuracy:  ${summary.accuracy}`);
  console.log(`  Precision: ${summary.precision}`);
  console.log(`  Recall:    ${summary.recall}`);
  console.log(`  F1 Score:  ${summary.f1Score}`);
  console.log(`  Avg Latency: ${summary.avgLatencyMs} ms`);
  console.log(`\nOutputs written to testing-data/\n`);
}

main().catch((err) => {
  console.error("Evaluation failed:", err);
  process.exit(1);
});
