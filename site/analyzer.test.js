/* Node.js tests for the browser analysis engine (node:test, zero dependencies).
 * Run with: node --test site/analyzer.test.js
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

global.window = global;
require('./analyzer.js');

const { analyzePassword, explainRules, SAMPLE_DATA } = global.window.Analyzer;

const EXPECTED = [
  ['', 0, 'Very Weak', 0.0],
  ['a', 17, 'Very Weak', 4.7],
  ['password', 25, 'Weak', 10.58],
  ['abc123', 14, 'Very Weak', 5.58],
  ['Password1', 40, 'Fair', 15.18],
  ['P@ssw0rd', 43, 'Fair', 14.75],
  ['vL8!qZ#2wR@6tY&1c', 100, 'Very Strong', 111.43],
  ['correct horse battery staple', 69, 'Strong', 96.36],
  ['aaaaaaaaaaaaaaaaaaaa', 19, 'Very Weak', 6.29],
  ['abcdefghijklmnop', 34, 'Weak', 9.75],
  ['1234567890123456', 12, 'Very Weak', 7.32],
];

test('scores, ratings and entropy match the Python engine', () => {
  for (const [password, score, rating, entropy] of EXPECTED) {
    const result = analyzePassword(password);
    assert.equal(result.score, score, `score mismatch for ${JSON.stringify(password)}`);
    assert.equal(result.rating, rating, `rating mismatch for ${JSON.stringify(password)}`);
    assert.equal(result.entropy_bits, entropy, `entropy mismatch for ${JSON.stringify(password)}`);
  }
});

test('character class flags are detected', () => {
  const result = analyzePassword('Ab1!');
  assert.equal(result.has_upper, true);
  assert.equal(result.has_lower, true);
  assert.equal(result.has_digit, true);
  assert.equal(result.has_special, true);
  assert.equal(result.char_classes, 4);
});

test('weak passwords produce actionable issues', () => {
  const common = analyzePassword('password');
  assert.ok(common.issues.some((issue) => issue.includes('common password')));
  assert.ok(common.suggestions.length > 0);

  const sequence = analyzePassword('abcdefghijklmnop');
  assert.ok(sequence.issues.some((issue) => issue.includes('sequence')));

  const repetition = analyzePassword('aaaaaaaaaaaaaaaaaaaa');
  assert.ok(repetition.issues.some((issue) => issue.includes('repetition')));

  const empty = analyzePassword('');
  assert.deepEqual(empty.issues, ['Empty password']);
});

test('strong passwords have no issues and hit the top band', () => {
  const result = analyzePassword('vL8!qZ#2wR@6tY&1c');
  assert.deepEqual(result.issues, []);
  assert.equal(result.rating, 'Very Strong');
  assert.equal(result.score, 100);
});

test('result never contains the original password', () => {
  const secret = 'Un1que!Secret#42';
  assert.equal(JSON.stringify(analyzePassword(secret)).includes(secret), false);
});

test('crack time is human readable and bounded', () => {
  assert.equal(analyzePassword('password').crack_time, 'less than a second');
  assert.equal(analyzePassword('vL8!qZ#2wR@6tY&1c').crack_time, 'longer than the age of the universe');
});

test('non-string input is coerced safely', () => {
  assert.equal(typeof analyzePassword(1234).score, 'number');
});

test('advanced structural patterns are detected', () => {
  assert.ok(analyzePassword('qwertyuiop123').patterns.includes('spatial'));
  assert.ok(analyzePassword('01011990').patterns.includes('date'));
  assert.ok(analyzePassword('aaaaaaaaaaaaaaaaaaaa').patterns.includes('repeat'));
  assert.deepEqual(analyzePassword('vL8!qZ#2wR@6tY&1c').patterns, []);
});

test('invariants hold for every sample password', () => {
  const bands = [[20, 'Very Weak'], [40, 'Weak'], [60, 'Fair'], [80, 'Strong'], [101, 'Very Strong']];
  for (const [, password] of global.window.Analyzer.SAMPLE_DATA) {
    const result = analyzePassword(password);
    assert.ok(result.score >= 0 && result.score <= 100);
    assert.ok(result.entropy_bits >= 0);
    assert.ok(result.crack_time.length > 0);
    assert.ok(result.char_classes <= 4);
    assert.ok(result.suggestions.length <= 6);
    const expected = bands.find(([ceiling]) => result.score < ceiling)[1];
    assert.equal(result.rating, expected);
  }
  for (const secret of ['X9#mL2@vT7!qR4$p', 'vL8!qZ#2wR@6tY&1c', 'Purple-Coffee-Mountain-42']) {
    assert.equal(JSON.stringify(analyzePassword(secret)).includes(secret), false);
  }
});

test('Structural Drift Index is deterministic, bounded and non-reversible', () => {
  const A = global.window.Analyzer;
  const first = A.structuralFingerprint(analyzePassword('X9#mL2@vT7!qR4$p'));
  const second = A.structuralFingerprint(analyzePassword('X9#mL2@vT7!qR4$p'));
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first).includes('X9#mL2'), false);

  const a = A.structuralFingerprint(analyzePassword('password'));
  const b = A.structuralFingerprint(analyzePassword('X9#mL2@vT7!qR4$p'));
  assert.equal(A.structuralDistance(a, a), 0);
  assert.equal(A.structuralDistance(a, b), A.structuralDistance(b, a));
  assert.ok(A.structuralDistance(a, b) >= 0 && A.structuralDistance(a, b) <= 1);
  assert.equal(A.portfolioDiversity([]), 1);
});

test('structural drift finds the nearest history entry', () => {
  const A = global.window.Analyzer;
  const target = analyzePassword('aaaaaaaaaaaaaaaaaaaa');
  const history = [
    { id: 1, analysis: analyzePassword('X9#mL2@vT7!qR4$p') },
    { id: 2, analysis: analyzePassword('aaaaaaaaaaaaaaaaaaaa') },
    { id: 3, analysis: analyzePassword('correct horse battery staple') },
  ];
  const drift = A.structuralDrift(target, history);
  assert.equal(drift.nearest_id, 2);
  assert.ok(drift.similarity > 0.99);
  assert.ok(drift.personal_risk >= 0 && drift.personal_risk <= 100);
  assert.ok(drift.advice.length > 0);
});

test('rules are structured and complete', () => {
  const rules = explainRules();
  assert.ok(rules.length >= 5);
  for (const rule of rules) {
    assert.equal(typeof rule.title, 'string');
    assert.equal(typeof rule.rule, 'string');
    assert.equal(typeof rule.why, 'string');
  }
});

test('sample dataset covers the 30-50 demo range with edge cases', () => {
  assert.ok(SAMPLE_DATA.length >= 30 && SAMPLE_DATA.length <= 50);
  const passwords = SAMPLE_DATA.map((item) => item[1]);
  assert.ok(passwords.includes(''));
  assert.ok(passwords.includes('password'));
  assert.ok(passwords.includes('aaaaaaaaaaaaaaaaaaaa'));
});
