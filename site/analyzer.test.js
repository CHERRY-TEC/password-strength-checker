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
  ['aaaaaaaaaaaaaaaaaaaa', 35, 'Weak', 49.35],
  ['abcdefghijklmnop', 40, 'Fair', 45.12],
  ['1234567890123456', 12, 'Very Weak', 7.77],
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
