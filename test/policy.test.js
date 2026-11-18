import test from 'node:test';
import assert from 'node:assert/strict';
import { packages, resolveUsageBucket } from '../src/policy.js';

test('first three successful generations are free across services', () => {
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 0, paidCredits: 0 }), 'free');
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 1, paidCredits: 0 }), 'free');
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 2, paidCredits: 0 }), 'free');
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 3, paidCredits: 0 }), null);
});

test('paid credits are used only after free requests are exhausted', () => {
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 1, paidCredits: 5 }), 'free');
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 3, paidCredits: 5 }), 'paid');
  assert.equal(resolveUsageBucket({ freeRequestsUsed: 3, paidCredits: 0 }), null);
});

test('package prices and credit counts match the agreed price list', () => {
  assert.deepEqual(packages, {
    mini: { priceRub: 200, credits: 3 },
    pro: { priceRub: 500, credits: 5 },
    max: { priceRub: 1000, credits: 10 }
  });
});
