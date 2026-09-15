import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RULE_TYPES, STEP_KINDS, OPS, MIN_SCENARIOS, sha256, canon,
  validTrace, validPolicy, checkTrace, appendAudit, verifyAudit,
  regressionGate, makeReceipt, verifyReceipt,
} from './kernel.mjs';

test('sha256 + canon + constants pinned', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256(3).ok, false);
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ x: 5 }), canon({ x: '5' }));
  assert.notEqual(canon({ x: null }), canon({ x: 0 }));
  assert.equal(MIN_SCENARIOS, 3);
  assert.deepEqual([...STEP_KINDS], ['input', 'tool', 'output']);
  assert.deepEqual([...OPS], ['eq', 'ne', 'lt', 'lte', 'gt', 'gte']);
  assert.equal(RULE_TYPES.length, 7);
});

// a clean support-agent trace: reads a ticket, looks it up, refunds, answers in JSON
const goodTrace = {
  agent: 'support-bot', runId: 'r1', steps: [
    { i: 0, kind: 'input', content: 'refund my order 5512, it arrived broken' },
    { i: 1, kind: 'tool', tool: 'lookup_order', content: '{"order":"5512","status":"delivered"}' },
    { i: 2, kind: 'tool', tool: 'issue_refund', content: '{"order":"5512","amount":1999}' },
    { i: 3, kind: 'output', content: 'Done: {"category":"refund","order":"5512","amount":1999}' },
  ],
};

test('validTrace: a good trace passes; every guard refuses', () => {
  assert.equal(validTrace(goodTrace), null);
  assert.match(validTrace(null), /is an object/);
  assert.match(validTrace({ ...goodTrace, agent: '' }), /agent name/);
  assert.match(validTrace({ ...goodTrace, runId: '' }), /runId/);
  assert.match(validTrace({ ...goodTrace, steps: [] }), /non-empty steps/);
  // out-of-order index
  assert.match(validTrace({ ...goodTrace, steps: [{ i: 1, kind: 'input', content: 'x' }] }), /wrong index/);
  // bad kind
  assert.match(validTrace({ ...goodTrace, steps: [{ i: 0, kind: 'think', content: 'x' }] }), /kind must be/);
  // tool step without a tool name
  assert.match(validTrace({ ...goodTrace, steps: [{ i: 0, kind: 'tool', content: 'x' }] }), /needs a tool name/);
  // non-string content
  assert.equal(validTrace({ ...goodTrace, steps: [{ i: 0, kind: 'input', content: 5 }] }) === null, false);
});

test('validPolicy: each rule shape refuses malformed input with its own why', () => {
  const P = (rule) => validPolicy({ name: 'p', rules: [rule] });
  assert.equal(P({ type: 'allowed-tools', tools: ['a'] }).ok, true);
  assert.match(P({ type: 'nope' }).why, /known type/);
  assert.match(P({ type: 'allowed-tools', tools: [] }).why, /non-empty tools/);
  assert.match(P({ type: 'allowed-tools', tools: ['a', ''] }).why, /non-empty strings/);
  assert.match(P({ type: 'must-call', tool: '' }).why, /needs a tool name/);
  assert.match(P({ type: 'output-json', required: 'x' }).why, /required-fields array/);
  assert.match(P({ type: 'output-json', required: ['a', 7] }).why, /non-empty strings/);
  assert.match(P({ type: 'no-content', substring: '' }).why, /non-empty substring/);
  assert.match(P({ type: 'invariant', field: '', op: 'eq', value: 1 }).why, /needs a field/);
  assert.match(P({ type: 'invariant', field: 'f', op: 'xx', value: 1 }).why, /op must be/);
  assert.match(P({ type: 'invariant', field: 'f', op: 'eq', value: null }).why, /number or string/);
  assert.match(P({ type: 'max-steps', n: 0 }).why, /positive integer/);
  assert.equal(P({ type: 'max-steps', n: 1.5 }).ok, false);
  assert.equal(validPolicy({ name: '', rules: [{ type: 'must-call', tool: 'x' }] }).ok, false);
  assert.equal(validPolicy({ name: 'p', rules: [] }).ok, false);
  assert.equal(validPolicy(null).ok, false);
});

// ── the heart: every rule type, PASS and FAIL, with the right violation
test('checkTrace: allowed-tools / forbidden-tools', () => {
  const allow = { name: 'p', rules: [{ type: 'allowed-tools', tools: ['lookup_order', 'issue_refund'] }] };
  assert.equal(checkTrace(goodTrace, allow).pass, true);
  const rogue = { ...goodTrace, steps: [...goodTrace.steps.slice(0, 2), { i: 2, kind: 'tool', tool: 'delete_account', content: '{}' }, { i: 3, kind: 'output', content: '{}' }] };
  const r = checkTrace(rogue, allow);
  assert.equal(r.pass, false);
  assert.equal(r.violations[0].step, 2);
  assert.match(r.violations[0].why, /allow-list: delete_account/);
  const forbid = { name: 'p', rules: [{ type: 'forbidden-tools', tools: ['delete_account'] }] };
  assert.equal(checkTrace(goodTrace, forbid).pass, true);
  assert.equal(checkTrace(rogue, forbid).pass, false);
  assert.match(checkTrace(rogue, forbid).violations[0].why, /forbidden tool: delete_account/);
});

test('checkTrace: must-call, output-json, no-content, max-steps, invariant', () => {
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'must-call', tool: 'issue_refund' }] }).pass, true);
  const miss = checkTrace(goodTrace, { name: 'p', rules: [{ type: 'must-call', tool: 'escalate' }] });
  assert.equal(miss.pass, false); assert.equal(miss.violations[0].step, -1); assert.match(miss.violations[0].why, /never called.*escalate/);

  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'output-json', required: ['category', 'order'] }] }).pass, true);
  const badOut = { ...goodTrace, steps: [...goodTrace.steps.slice(0, 3), { i: 3, kind: 'output', content: 'sorry, no idea' }] };
  const bo = checkTrace(badOut, { name: 'p', rules: [{ type: 'output-json', required: ['category'] }] });
  assert.equal(bo.pass, false); assert.match(bo.violations[0].why, /not a JSON object/);
  const missField = checkTrace(goodTrace, { name: 'p', rules: [{ type: 'output-json', required: ['refundApproved'] }] });
  assert.match(missField.violations[0].why, /missing the required field: refundApproved/);

  const leak = { ...goodTrace, steps: [...goodTrace.steps.slice(0, 3), { i: 3, kind: 'output', content: 'ok sk-live-ABCD {"category":"refund"}' }] };
  assert.equal(checkTrace(leak, { name: 'p', rules: [{ type: 'no-content', substring: 'sk-live-' }] }).pass, false);
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'no-content', substring: 'sk-live-' }] }).pass, true);

  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'max-steps', n: 4 }] }).pass, true);   // exactly the ceiling
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'max-steps', n: 3 }] }).pass, false);  // one over

  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'amount', op: 'lte', value: 2000 }] }).pass, true);
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'amount', op: 'lte', value: 1999 }] }).pass, true);   // eq boundary
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'amount', op: 'lt', value: 1999 }] }).pass, false);   // strict
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'category', op: 'eq', value: 'refund' }] }).pass, true);
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'category', op: 'ne', value: 'refund' }] }).pass, false);
  assert.match(checkTrace(goodTrace, { name: 'p', rules: [{ type: 'invariant', field: 'ghost', op: 'eq', value: 1 }] }).violations[0].why, /field is absent/);
});

test('checkTrace: refusals, and the final output is the one checked (not an earlier one)', () => {
  assert.equal(checkTrace(null, { name: 'p', rules: [{ type: 'max-steps', n: 1 }] }).ok, false);
  assert.equal(checkTrace(goodTrace, { name: 'p', rules: [] }).ok, false);
  // an earlier output that would pass must NOT save a bad final output
  const twoOut = { agent: 'a', runId: 'r', steps: [
    { i: 0, kind: 'output', content: '{"category":"refund"}' },
    { i: 1, kind: 'output', content: 'oops no json' }] };
  assert.equal(checkTrace(twoOut, { name: 'p', rules: [{ type: 'output-json', required: ['category'] }] }).pass, false);
});

// ── the audit ledger
test('audit ledger: appends, verifies, tamper breaks at the link', () => {
  const pol = { name: 'p', rules: [{ type: 'must-call', tool: 'issue_refund' }] };
  let c = appendAudit([], goodTrace, pol).chain;
  c = appendAudit(c, { ...goodTrace, runId: 'r2' }, pol).chain;
  assert.equal(c[0].prevHash, 'GENESIS');
  assert.equal(c[0].entry.pass, true);
  assert.equal(verifyAudit(c).valid, true);
  assert.equal(verifyAudit(c).length, 2);
  assert.equal(verifyAudit([]).valid, true);
  const tampered = c.map((x, i) => i === 0 ? { ...x, entry: { ...x.entry, pass: false } } : x);
  assert.equal(verifyAudit(tampered).valid, false);
  assert.equal(verifyAudit(tampered).brokenAt, 0);
  assert.equal(verifyAudit([c[1], c[0]]).valid, false);   // reorder
  assert.equal(appendAudit('x', goodTrace, pol).ok, false);
  assert.equal(appendAudit([], { ...goodTrace, steps: [] }, pol).ok, false);
  // forgeries: string entry with honest hash, array link
  const fh = sha256('GENESIS|' + '"x"').hash;
  assert.equal(verifyAudit([{ seq: 0, prevHash: 'GENESIS', hash: fh, entry: 'x' }]).valid, false);
  const arr = []; arr.seq = 0; arr.prevHash = 'GENESIS'; arr.hash = sha256('GENESIS|{}').hash; arr.entry = {};
  assert.equal(verifyAudit([arr]).valid, false);
});

// ── the regression gate + receipt
function scen(name, trace) { return { scenario: name, trace }; }
const pol = { name: 'refund-policy', rules: [{ type: 'allowed-tools', tools: ['lookup_order', 'issue_refund'] }, { type: 'output-json', required: ['category'] }] };
const s1 = scen('happy', goodTrace);
const s2 = scen('also-fine', { ...goodTrace, runId: 'r2' });
const s3 = scen('third', { ...goodTrace, runId: 'r3' });
const sBad = scen('rogue', { agent: 'support-bot', runId: 'rb', steps: [{ i: 0, kind: 'tool', tool: 'delete_account', content: '{}' }, { i: 1, kind: 'output', content: '{"category":"x"}' }] });

test('regressionGate: PASSES only when ALL scenarios pass, and needs MIN_SCENARIOS to certify', () => {
  const g = regressionGate('support-bot', pol, [s1, s2, s3]);
  assert.equal(g.verdict, 'PASSES');
  assert.equal(g.certified, true);
  assert.equal(g.passed, 3);
  // one rogue → FAILS, not certified
  const f = regressionGate('support-bot', pol, [s1, sBad, s3]);
  assert.equal(f.verdict, 'FAILS');
  assert.equal(f.certified, false);
  assert.match(f.why, /1 of 3 scenarios violated/);
  // exactly MIN passes; MIN-1 never certifies even if all pass (kills >= vs >)
  assert.equal(regressionGate('a', pol, [s1, s2]).certified, false);
  assert.match(regressionGate('a', pol, [s1, s2]).why, new RegExp('fewer than ' + MIN_SCENARIOS));
  assert.equal(regressionGate('a', pol, [s1, s2]).verdict, 'PASSES');   // it passed, just not certifiable
  assert.equal(regressionGate('', pol, [s1]).ok, false);
  assert.equal(regressionGate('a', pol, []).ok, false);
  assert.equal(regressionGate('a', { name: 'p', rules: [] }, [s1]).ok, false);
  assert.equal(regressionGate('a', pol, [{ scenario: '', trace: goodTrace }]).ok, false);
});

test('receipt: sealed, tamper shows, and a FAILS receipt is first-class', () => {
  const g = regressionGate('support-bot', pol, [s1, s2, s3]);
  const r = makeReceipt(g, { scoredAt: '2026-09-15T12:00:00Z' });
  assert.equal(r.ok, true);
  assert.equal(r.receipt.verdict, 'PASSES');
  assert.equal(r.receipt.certified, true);
  assert.match(r.receipt.scope, /not that its answers are/);
  assert.equal(verifyReceipt(r.receipt).valid, true);
  assert.equal(verifyReceipt({ ...r.receipt, verdict: 'FAILS' }).valid, false);
  assert.equal(verifyReceipt({ ...r.receipt, passed: 99 }).valid, false);
  assert.equal(verifyReceipt({ ...r.receipt, certified: false }).valid, false);
  assert.equal(verifyReceipt({ ...r.receipt, hash: 'f'.repeat(64) }).valid, false);
  assert.equal(verifyReceipt({ kind: 'agent-proof-receipt' }).ok, false);
  assert.equal(verifyReceipt('x').ok, false);
  assert.equal(makeReceipt({ ok: false }, { scoredAt: 't' }).ok, false);
  assert.equal(makeReceipt(g, {}).ok, false);
  // a FAILS receipt verifies just as well — the gate can say no
  const f = makeReceipt(regressionGate('support-bot', pol, [s1, sBad, s3]), { scoredAt: '2026-09-15T12:00:00Z' });
  assert.equal(f.receipt.verdict, 'FAILS');
  assert.equal(verifyReceipt(f.receipt).valid, true);
});

// ═══ kill probes ════════════════════════════════════════════════════════════════════════════════
test('kill: clause isolation on validTrace and validRule via forged arrays / numeric fields', () => {
  const arrStep = Object.assign([], { i: 0, kind: 'input', content: 'x' });
  assert.match(validTrace({ agent: 'a', runId: 'r', steps: [arrStep] }), /must be an object/);
  assert.equal(validPolicy({ name: 'p', rules: [Object.assign([], { type: 'must-call', tool: 'x' })] }).ok, false);
  // invariant with a string value + eq works; lt on strings does NOT hold (needs numbers)
  const t = { agent: 'a', runId: 'r', steps: [{ i: 0, kind: 'output', content: '{"s":"hi"}' }] };
  assert.equal(checkTrace(t, { name: 'p', rules: [{ type: 'invariant', field: 's', op: 'eq', value: 'hi' }] }).pass, true);
  assert.equal(checkTrace(t, { name: 'p', rules: [{ type: 'invariant', field: 's', op: 'lt', value: 'zzz' }] }).pass, false);  // string < string not supported → violation
});

test('kill: every rule refusal names its true reason (clauses distinguishable)', () => {
  const P = (rule) => validPolicy({ name: 'p', rules: [rule] }).why;
  assert.match(P({ type: 'invariant', field: 'f', op: 'eq' }), /number or string/);   // missing value, not op
  assert.match(P({ type: 'output-json' }), /required-fields array/);                    // missing required, not type
  assert.match(P({ type: 'max-steps' }), /positive integer/);
});

test('kill: all six invariant ops at their exact boundary', () => {
  const T = (v) => ({ agent: 'a', runId: 'r', steps: [{ i: 0, kind: 'output', content: '{"n":' + v + '}' }] });
  const C = (op, value, v) => checkTrace(T(v), { name: 'p', rules: [{ type: 'invariant', field: 'n', op, value }] }).pass;
  // gt: 5 > 5 false, 6 > 5 true
  assert.equal(C('gt', 5, 5), false); assert.equal(C('gt', 5, 6), true);
  // gte: 5 >= 5 true, 4 >= 5 false
  assert.equal(C('gte', 5, 5), true); assert.equal(C('gte', 5, 4), false);
  // lt: 5 < 5 false, 4 < 5 true
  assert.equal(C('lt', 5, 5), false); assert.equal(C('lt', 5, 4), true);
  // lte: 5 <= 5 true, 6 <= 5 false
  assert.equal(C('lte', 5, 5), true); assert.equal(C('lte', 5, 6), false);
  // eq / ne pin the === op branch and distinguish from the comparison branches
  assert.equal(C('eq', 5, 5), true); assert.equal(C('eq', 5, 6), false);
  assert.equal(C('ne', 5, 6), true); assert.equal(C('ne', 5, 5), false);
});

test('kill: isNum rejects NaN/Infinity (kills && → ||) via invariant-value validation', () => {
  const P = (value) => validPolicy({ name: 'p', rules: [{ type: 'invariant', field: 'f', op: 'eq', value }] }).ok;
  assert.equal(P(5), true);
  assert.equal(P(NaN), false);        // typeof number but not finite — the && mutant would accept it
  assert.equal(P(Infinity), false);
  assert.equal(P('x'), true);         // strings are allowed
});

test('kill: max-steps n=1 is a valid rule (kills < vs <=)', () => {
  assert.equal(validPolicy({ name: 'p', rules: [{ type: 'max-steps', n: 1 }] }).ok, true);
});

test('kill: regressionGate + makeReceipt clause isolation (forged arrays, numeric fields)', () => {
  const arrScen = Object.assign([], { scenario: 'x', trace: goodTrace });
  assert.equal(regressionGate('a', pol, [arrScen]).ok, false);                 // array with a scenario prop — isObj clause
  assert.equal(regressionGate('a', pol, [{ scenario: 7, trace: goodTrace }]).ok, false);   // numeric scenario — isStr clause
  const arrGate = Object.assign([], { ok: true, verdict: 'PASSES', agent: 'a', policy: 'p', total: 3, passed: 3 });
  assert.equal(makeReceipt(arrGate, { scoredAt: 't' }).ok, false);             // array with ok+verdict — isObj clause
  assert.equal(makeReceipt({ ok: true, verdict: 7 }, { scoredAt: 't' }).ok, false);   // numeric verdict — isStr clause
});
