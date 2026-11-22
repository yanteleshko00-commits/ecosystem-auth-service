export const packages = Object.freeze({
  mini: Object.freeze({ priceRub: 200, credits: 3 }),
  pro: Object.freeze({ priceRub: 500, credits: 5 }),
  max: Object.freeze({ priceRub: 1000, credits: 10 })
});

export function resolveUsageBucket({ freeRequestsUsed, paidCredits }) {
  if (Number.isInteger(freeRequestsUsed) && freeRequestsUsed < 3) return 'free';
  if (Number.isInteger(paidCredits) && paidCredits > 0) return 'paid';
  return null;
}
