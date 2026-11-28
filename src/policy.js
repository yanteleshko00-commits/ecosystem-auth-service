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

export const subscriptionLimits=Object.freeze({requestsPerHour:30,concurrent:4});
export const productNames=Object.freeze(['chat','game','image','text','math','project','argosha']);
export function subscriptionStatus(until,now=Date.now()){
 const timestamp=until?new Date(until).getTime():NaN;
 return {active:Number.isFinite(timestamp)&&timestamp>now,expiresAt:Number.isFinite(timestamp)?new Date(timestamp).toISOString():null,limits:subscriptionLimits};
}
export function reservationLimit({hourly,active}){
 return active>=subscriptionLimits.concurrent?'concurrency_limit':hourly>=subscriptionLimits.requestsPerHour?'account_rate_limited':null;
}
