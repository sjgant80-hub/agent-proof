// agent-proof — the deterministic gate + tamper-evident audit trail for AI agents. The pure core:
// an agent RUN produces a trace (input → tool calls → output); a POLICY is a set of deterministic
// rules (allowed/forbidden/required tools, output shape, forbidden content, numeric invariants,
// a step ceiling). checkTrace measures a trace against a policy and names every violation — NO
// LLM judge, because a model grading a model gives false confidence. Every checked run lands on a
// SHA-256 audit ledger (tamper breaks the chain). A regression gate proves an agent still passes a
// fixed scenario suite, and seals a signable receipt that can, and does, say FAILS.
// No I/O. Pure and total: garbage in → { ok:false, why }, never a throw.

export const RULE_TYPES = Object.freeze(['allowed-tools', 'forbidden-tools', 'must-call', 'output-json', 'no-content', 'invariant', 'max-steps']);
export const STEP_KINDS = Object.freeze(['input', 'tool', 'output']);
export const OPS = Object.freeze(['eq', 'ne', 'lt', 'lte', 'gt', 'gte']);
export const MIN_SCENARIOS = 3;   // a pass on fewer than this is not evidence an agent is production-safe

const isStr = (v) => typeof v === 'string';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;

// ── SHA-256 + canonical JSON (the estate's proven pair) ─────────────────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the trace: an agent run, as steps ───────────────────────────────────────────────────────────
export function validTrace(t) {
  if (!isObj(t)) return 'a trace is an object';
  if (!isStr(t.agent) || t.agent.length === 0) return 'a trace needs an agent name';
  if (!isStr(t.runId) || t.runId.length === 0) return 'a trace needs a runId';
  if (!Array.isArray(t.steps) || t.steps.length === 0) return 'a trace needs a non-empty steps array';
  for (let i = 0; i < t.steps.length; i++) {
    const s = t.steps[i];
    if (!isObj(s)) return 'step ' + i + ' must be an object';
    if (s.i !== i) return 'step ' + i + ' has the wrong index (steps are 0-based and in order)';
    if (!isStr(s.kind) || !STEP_KINDS.includes(s.kind)) return 'step ' + i + ' kind must be one of ' + STEP_KINDS.join(', ');
    if (!isStr(s.content)) return 'step ' + i + ' needs string content';
    if (s.kind === 'tool' && (!isStr(s.tool) || s.tool.length === 0)) return 'step ' + i + ' is a tool call and needs a tool name';
  }
  return null;
}

// ── the policy: deterministic rules ─────────────────────────────────────────────────────────────
function validRule(r) {
  if (!isObj(r) || !isStr(r.type) || !RULE_TYPES.includes(r.type)) return 'each rule needs a known type';
  if (r.type === 'allowed-tools' || r.type === 'forbidden-tools') {
    if (!Array.isArray(r.tools) || r.tools.length === 0) return r.type + ' needs a non-empty tools array';
    for (const x of r.tools) if (!isStr(x) || x.length === 0) return r.type + ' tool names must be non-empty strings';
  }
  if (r.type === 'must-call' && (!isStr(r.tool) || r.tool.length === 0)) return 'must-call needs a tool name';
  if (r.type === 'output-json') {
    if (!Array.isArray(r.required)) return 'output-json needs a required-fields array';
    for (const f of r.required) if (!isStr(f) || f.length === 0) return 'output-json required fields must be non-empty strings';
  }
  if (r.type === 'no-content' && (!isStr(r.substring) || r.substring.length === 0)) return 'no-content needs a non-empty substring';
  if (r.type === 'invariant') {
    if (!isStr(r.field) || r.field.length === 0) return 'invariant needs a field';
    if (!isStr(r.op) || !OPS.includes(r.op)) return 'invariant op must be one of ' + OPS.join(', ');
    if (!isNum(r.value) && !isStr(r.value)) return 'invariant value must be a number or string';
  }
  if (r.type === 'max-steps' && (!isInt(r.n) || r.n < 1)) return 'max-steps needs a positive integer n';
  return null;
}

export function validPolicy(p) {
  if (!isObj(p)) return { ok: false, why: 'a policy is an object' };
  if (!isStr(p.name) || p.name.length === 0) return { ok: false, why: 'a policy needs a name' };
  if (!Array.isArray(p.rules) || p.rules.length === 0) return { ok: false, why: 'a policy needs a non-empty rules array' };
  for (const [i, r] of p.rules.entries()) { const bad = validRule(r); if (bad) return { ok: false, why: 'rule ' + i + ': ' + bad }; }
  return { ok: true };
}

// find the first balanced JSON object in a string (agents wrap output in prose)
function firstObj(text) {
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0, inStr = false, escN = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escN) { escN = false; continue; }
    if (c === '\\') { escN = true; continue; }
    if (c === '"') inStr = !inStr;
    if (inStr) continue;
    if (c === '{') depth++;
    if (c === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.slice(start, i + 1)); } catch (e) { return null; } } }
  }
  return null;
}

function checkRule(rule, trace) {
  const tools = trace.steps.filter((s) => s.kind === 'tool');
  const outputs = trace.steps.filter((s) => s.kind === 'output');
  const finalOut = outputs.length ? outputs[outputs.length - 1] : null;
  if (rule.type === 'allowed-tools') {
    for (const s of tools) if (!rule.tools.includes(s.tool)) return { step: s.i, why: 'called a tool not in the allow-list: ' + s.tool };
    return null;
  }
  if (rule.type === 'forbidden-tools') {
    for (const s of tools) if (rule.tools.includes(s.tool)) return { step: s.i, why: 'called a forbidden tool: ' + s.tool };
    return null;
  }
  if (rule.type === 'must-call') {
    return tools.some((s) => s.tool === rule.tool) ? null : { step: -1, why: 'never called the required tool: ' + rule.tool };
  }
  if (rule.type === 'output-json') {
    if (!finalOut) return { step: -1, why: 'no output step to check' };
    const obj = firstObj(finalOut.content);
    if (!obj) return { step: finalOut.i, why: 'the final output is not a JSON object' };
    for (const f of rule.required) if (!(f in obj)) return { step: finalOut.i, why: 'the output is missing the required field: ' + f };
    return null;
  }
  if (rule.type === 'no-content') {
    for (const s of trace.steps) if (s.content.includes(rule.substring)) return { step: s.i, why: 'content contained a forbidden substring' };
    return null;
  }
  if (rule.type === 'invariant') {
    if (!finalOut) return { step: -1, why: 'no output step to check the invariant on' };
    const obj = firstObj(finalOut.content);
    if (!obj || !(rule.field in obj)) return { step: finalOut.i, why: 'the invariant field is absent: ' + rule.field };
    const got = obj[rule.field], want = rule.value;
    let held;
    if (rule.op === 'eq') held = got === want;
    else if (rule.op === 'ne') held = got !== want;
    else held = isNum(got) && isNum(want) && (rule.op === 'lt' ? got < want : rule.op === 'lte' ? got <= want : rule.op === 'gt' ? got > want : got >= want);
    return held ? null : { step: finalOut.i, why: 'invariant failed: ' + rule.field + ' ' + rule.op + ' ' + JSON.stringify(want) + ' (was ' + JSON.stringify(got) + ')' };
  }
  // max-steps
  return trace.steps.length <= rule.n ? null : { step: rule.n, why: 'the run took ' + trace.steps.length + ' steps, over the ceiling of ' + rule.n };
}

/** checkTrace(trace, policy) — deterministic. Returns { pass, violations, checked }. No judge. */
export function checkTrace(trace, policy) {
  const bt = validTrace(trace);
  if (bt) return { ok: false, why: bt };
  const vp = validPolicy(policy);
  if (!vp.ok) return vp;
  const violations = [];
  for (const rule of policy.rules) {
    const v = checkRule(rule, trace);
    if (v) violations.push({ rule: rule.type, step: v.step, why: v.why });
  }
  return { ok: true, pass: violations.length === 0, violations, checked: policy.rules.length };
}

// ── the audit ledger: every checked run, hash-chained ───────────────────────────────────────────
export function appendAudit(chain, trace, policy) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the audit ledger is an array' };
  const r = checkTrace(trace, policy);
  if (!r.ok) return { ok: false, why: r.why };
  const th = sha256(canon(trace));
  const entry = { agent: trace.agent, runId: trace.runId, policy: policy.name, pass: r.pass, violations: r.violations.length, traceHash: th.hash };
  const prevHash = chain.length === 0 ? 'GENESIS' : chain[chain.length - 1].hash;
  const h = sha256(prevHash + '|' + canon(entry));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, chain: [...chain, { seq: chain.length, prevHash, hash: h.hash, entry }], verdict: r };
}

export function verifyAudit(chain) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the audit ledger is an array' };
  for (let i = 0; i < chain.length; i++) {
    const item = chain[i];
    if (!isObj(item) || !isStr(item.hash) || !isStr(item.prevHash) || !isObj(item.entry)) return { ok: true, valid: false, brokenAt: i };
    if (item.seq !== i) return { ok: true, valid: false, brokenAt: i };
    const expectedPrev = i === 0 ? 'GENESIS' : chain[i - 1].hash;
    if (item.prevHash !== expectedPrev) return { ok: true, valid: false, brokenAt: i };
    const h = sha256(item.prevHash + '|' + canon(item.entry));
    if (!h.ok || h.hash !== item.hash) return { ok: true, valid: false, brokenAt: i };
  }
  return { ok: true, valid: true, length: chain.length };
}

// ── the regression gate: an agent passes a fixed scenario suite, or it FAILS ────────────────────
export function regressionGate(agent, policy, results) {
  if (!isStr(agent) || agent.length === 0) return { ok: false, why: 'a gate run names the agent' };
  const vp = validPolicy(policy);
  if (!vp.ok) return vp;
  if (!Array.isArray(results) || results.length === 0) return { ok: false, why: 'the gate takes a non-empty results array' };
  const scored = [];
  let passed = 0;
  for (const [i, s] of results.entries()) {
    if (!isObj(s) || !isStr(s.scenario) || s.scenario.length === 0) return { ok: false, why: 'result ' + i + ' needs a scenario name' };
    const r = checkTrace(s.trace, policy);
    if (!r.ok) return { ok: false, why: 'scenario ' + s.scenario + ': ' + r.why };
    if (r.pass) passed++;
    scored.push({ scenario: s.scenario, pass: r.pass, violations: r.violations });
  }
  const verdict = passed === results.length ? 'PASSES' : 'FAILS';
  const certified = results.length >= MIN_SCENARIOS && passed === results.length;
  return { ok: true, agent, policy: policy.name, total: results.length, passed, verdict, certified, scenarios: scored,
    why: certified ? 'every scenario passed the policy, on ' + results.length + ' scenarios'
      : results.length < MIN_SCENARIOS ? 'not certifiable: fewer than ' + MIN_SCENARIOS + ' scenarios is not evidence'
      : 'not certified: ' + (results.length - passed) + ' of ' + results.length + ' scenarios violated the policy' };
}

// ── the receipt: measured, canonically hashed, tamper shows; a FAILS receipt is first-class ─────
export function makeReceipt(gate, meta) {
  if (!isObj(gate) || gate.ok !== true || !isStr(gate.verdict)) return { ok: false, why: 'makeReceipt takes a successful regressionGate result' };
  if (!isObj(meta) || !isStr(meta.scoredAt) || meta.scoredAt.length === 0) return { ok: false, why: 'meta needs a scoredAt timestamp' };
  const body = {
    v: 1, kind: 'agent-proof-receipt',
    agent: gate.agent, policy: gate.policy, scenarios: gate.total, passed: gate.passed,
    verdict: gate.verdict, certified: gate.certified, scoredAt: meta.scoredAt,
    scope: 'deterministic policy compliance on this scenario set — proves the agent obeyed its rules, not that its answers are "good"',
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, receipt: { ...body, hash: h.hash } };
}

export function verifyReceipt(r) {
  if (!isObj(r) || !isStr(r.hash)) return { ok: false, why: 'a receipt is an object with a hash' };
  if (r.kind !== 'agent-proof-receipt') return { ok: false, why: 'not an agent-proof receipt' };
  const body = { ...r };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== r.hash) return { ok: true, valid: false, why: 'hash mismatch — the receipt does not match its own facts' };
  return { ok: true, valid: true, why: 'receipt intact' };
}
