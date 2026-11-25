import test from 'node:test';
import assert from 'node:assert/strict';
import {validRateEmail,takePersistentRate} from '../src/rate-limits.js';
test('email key normalizes valid addresses and rejects malformed addresses',()=>{
 for(const email of ['a@b.com','user@example.com','test@mail.ru'])assert.equal(validRateEmail(email),email);
 assert.equal(validRateEmail(' USER@EXAMPLE.COM '),'user@example.com');
 for(const email of ['a b@c.com','a@b','a@@b.com',''])assert.equal(validRateEmail(email),'');
});
test('persistent limiter fails closed and hashes identifiers',async()=>{
 process.env.TOKEN_PEPPER='unit-test-only-pepper-32-characters';
 let args;
 const db={query:async(sql,params)=>{args=params;assert.match(sql,/ON CONFLICT/);return {rowCount:1};}};
 assert.equal(await takePersistentRate(db,'admin','127.0.0.1',5,900),true);
 assert.match(args[0],/^[a-f0-9]{64}$/);assert.equal(args[1],900);assert.equal(args[2],5);
 assert.equal(await takePersistentRate({query:async()=>({rowCount:0})},'admin','127.0.0.1',5,900),false);
 assert.equal(await takePersistentRate(db,'admin','',5,900),false);
});
