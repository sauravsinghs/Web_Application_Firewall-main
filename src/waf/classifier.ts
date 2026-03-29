import type { Rule, RuleMatch, ClassifyResult } from "./types.js";

const RULES: Rule[] = [
  // --- SQL Injection ---
  { name: "sqli-tautology",      pattern: /['"]?\s*OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,               weight: 1.0, category: "sqli" },
  { name: "sqli-tautology-str",  pattern: /['"]?\s*OR\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]/i,         weight: 1.0, category: "sqli" },
  { name: "sqli-union-select",   pattern: /UNION\s+(ALL\s+)?SELECT/i,                                  weight: 1.0, category: "sqli" },
  { name: "sqli-drop",           pattern: /DROP\s+(TABLE|DATABASE|INDEX)/i,                             weight: 1.0, category: "sqli" },
  { name: "sqli-comment-trail",  pattern: /['"].*--/,                                                   weight: 1.0, category: "sqli" },
  { name: "sqli-inline-comment", pattern: /\/\*.*?\*\//,                                                weight: 0.5, category: "sqli" },
  { name: "sqli-stacked",        pattern: /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)/i,        weight: 1.0, category: "sqli" },
  { name: "sqli-waitfor",        pattern: /WAITFOR\s+DELAY/i,                                           weight: 1.0, category: "sqli" },
  { name: "sqli-sleep",          pattern: /SLEEP\s*\(\s*\d+\s*\)/i,                                     weight: 1.0, category: "sqli" },
  { name: "sqli-benchmark",      pattern: /BENCHMARK\s*\(/i,                                            weight: 1.0, category: "sqli" },
  { name: "sqli-information",    pattern: /INFORMATION_SCHEMA/i,                                         weight: 1.0, category: "sqli" },
  { name: "sqli-order-by-probe", pattern: /ORDER\s+BY\s+\d{2,}/i,                                      weight: 0.7, category: "sqli" },
  { name: "sqli-hex-literal",    pattern: /0x[0-9a-fA-F]{8,}/,                                          weight: 0.5, category: "sqli" },

  // --- XSS ---
  { name: "xss-script-tag",      pattern: /<\s*script[\s>]/i,                                           weight: 1.0, category: "xss" },
  { name: "xss-event-handler",   pattern: /on(load|error|focus|click|mouseover|submit|input|change)\s*=/i, weight: 1.0, category: "xss" },
  { name: "xss-javascript-uri",  pattern: /javascript\s*:/i,                                            weight: 1.0, category: "xss" },
  { name: "xss-img-onerror",     pattern: /<\s*img[^>]+onerror/i,                                       weight: 1.0, category: "xss" },
  { name: "xss-svg-onload",      pattern: /<\s*svg[^>]+onload/i,                                        weight: 1.0, category: "xss" },
  { name: "xss-body-event",      pattern: /<\s*body[^>]+on\w+\s*=/i,                                    weight: 1.0, category: "xss" },
  { name: "xss-iframe",          pattern: /<\s*iframe/i,                                                 weight: 1.0, category: "xss" },
  { name: "xss-data-uri",        pattern: /data\s*:\s*text\/html/i,                                     weight: 0.7, category: "xss" },
  { name: "xss-eval",            pattern: /\beval\s*\(/i,                                                weight: 0.6, category: "xss" },
  { name: "xss-document-cookie", pattern: /document\s*\.\s*cookie/i,                                    weight: 0.8, category: "xss" },
  { name: "xss-alert",           pattern: /alert\s*\(/i,                                                 weight: 0.5, category: "xss" },

  // --- Path Traversal ---
  { name: "traversal-dotdot",    pattern: /\.\.[/\\]/,                                                   weight: 1.0, category: "traversal" },
  { name: "traversal-etc",       pattern: /\/etc\/(passwd|shadow|hosts)/i,                               weight: 1.0, category: "traversal" },
  { name: "traversal-win",       pattern: /(\\|\/)(windows|winnt|system32|boot\.ini)/i,                  weight: 1.0, category: "traversal" },
  { name: "traversal-null-byte", pattern: /%00/,                                                          weight: 0.8, category: "traversal" },
  { name: "traversal-encoded",   pattern: /(%2e|\.){2}(%2f|%5c|\/|\\)/i,                                weight: 1.0, category: "traversal" },

  // --- Command Injection ---
  { name: "cmdi-pipe",           pattern: /\|\s*(cat|ls|dir|whoami|id|uname|net\s)/i,                   weight: 1.0, category: "cmdi" },
  { name: "cmdi-semicolon",      pattern: /;\s*(cat|ls|dir|whoami|id|uname|rm|del|net\s)/i,             weight: 1.0, category: "cmdi" },
  { name: "cmdi-backtick",       pattern: /`[^`]+`/,                                                     weight: 1.0, category: "cmdi" },
  { name: "cmdi-dollar-paren",   pattern: /\$\([^)]+\)/,                                                 weight: 1.0, category: "cmdi" },
  { name: "cmdi-uid-root",       pattern: /uid=\d+\(root\)/,                                             weight: 1.0, category: "cmdi" },
  { name: "cmdi-nc-reverse",     pattern: /\bnc\s+-\w*e\s/i,                                             weight: 1.0, category: "cmdi" },

  // --- Header Injection ---
  { name: "header-crlf",         pattern: /%0[dD]%0[aA]/,                                                weight: 1.0, category: "header-injection" },
  { name: "header-newline",      pattern: /\r\n|\n/,                                                     weight: 0.3, category: "header-injection" },

  // --- Encoding Abuse ---
  { name: "encoding-double",     pattern: /%25[0-9a-fA-F]{2}/,                                           weight: 1.0, category: "encoding" },
  { name: "encoding-overlong",   pattern: /%c0%af|%c1%1c/i,                                              weight: 1.0, category: "encoding" },
];

const DEFAULT_THRESHOLD = 1.0;

export function classifyRequest(
  path: string,
  body: string,
  threshold: number = DEFAULT_THRESHOLD,
): ClassifyResult {
  const decoded = decodeInput(path) + " " + decodeInput(body);
  const raw = path + " " + body;

  let score = 0;
  const ruleMatches: RuleMatch[] = [];

  for (const rule of RULES) {
    const target =
      rule.category === "encoding" || rule.category === "header-injection"
        ? raw
        : decoded;
    if (rule.pattern.test(target)) {
      score += rule.weight;
      ruleMatches.push({
        rule: rule.name,
        category: rule.category,
        weight: rule.weight,
      });
    }
  }

  return {
    malicious: score >= threshold,
    score: Math.round(score * 1000) / 1000,
    threshold,
    ruleMatches,
  };
}

function decodeInput(input: string): string {
  try {
    return decodeURIComponent(input.replace(/\+/g, " "));
  } catch {
    return input;
  }
}

export { RULES, DEFAULT_THRESHOLD };
