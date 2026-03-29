export interface Rule {
  name: string;
  pattern: RegExp;
  weight: number;
  category: "sqli" | "xss" | "traversal" | "cmdi" | "header-injection" | "encoding";
}

export interface RuleMatch {
  rule: string;
  category: string;
  weight: number;
}

export interface ClassifyResult {
  malicious: boolean;
  score: number;
  threshold: number;
  ruleMatches: RuleMatch[];
}

export interface WafEvent {
  timestamp: string;
  method: string;
  path: string;
  ip: string;
  blocked: boolean;
  reason: "rule" | "rate-limit" | "allowed";
  score: number;
  threshold: number;
  ruleMatches: RuleMatch[];
  statusCode: number;
  latencyMs: number;
}

export interface Metrics {
  total: number;
  blocked: number;
  allowed: number;
  rateLimited: number;
  avgLatencyMs: number;
}
