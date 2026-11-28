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

import {subscriptionStatus,reservationLimit} from '../src/policy.js';
test('subscription expiry and account-wide limits',()=>{assert.equal(subscriptionStatus('2030-01-01',Date.parse('2029-01-01')).active,true);assert.equal(subscriptionStatus('2030-01-01',Date.parse('2030-01-01')).active,false);assert.equal(subscriptionStatus(null).active,false);assert.equal(reservationLimit({hourly:30,active:0}),'account_rate_limited');assert.equal(reservationLimit({hourly:4,active:4}),'concurrency_limit');assert.equal(reservationLimit({hourly:29,active:3}),null);});
