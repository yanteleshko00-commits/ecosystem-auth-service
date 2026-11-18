import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

function safeNextPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  return value;
}
function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

test('safeNextPath permits internal relative paths only', () => {
  assert.equal(safeNextPath('/oauth/authorize?state=abc'), '/oauth/authorize?state=abc');
  assert.equal(safeNextPath('//attacker.example'), '/');
  assert.equal(safeNextPath('https://attacker.example'), '/');
  assert.equal(safeNextPath('/\\attacker'), '/');
});

test('constant-time text comparison rejects different values and lengths', () => {
  assert.equal(timingSafeEqualText('secret', 'secret'), true);
  assert.equal(timingSafeEqualText('secret', 'secrets'), false);
  assert.equal(timingSafeEqualText('secret', 'other'), false);
});
