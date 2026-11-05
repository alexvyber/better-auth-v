import {it,expect} from 'vitest';
import {openAPI} from 'better-auth/plugins';
import {getTestInstance} from './harness/test-instance.js';
it('validates callback POST inputs and preserves cookie-bearing CSRF checks before redirecting',async()=>{
 const ready=await getTestInstance({plugins:[openAPI()]},{disableTestUser:true});
 const target='http://localhost:3000/api/auth/callback/tinyauth';
 const post=(body:string,headers:Record<string,string>={},query='')=>ready.auth.handler(new Request(target+query,{method:'POST',headers:{'content-type':'application/json',...headers},body}));
 for(const input of [null,1,false,[],{}]){
  expect((await post(JSON.stringify({code:input}))).status).toBe(400);
 }
 expect((await post('{')).status).toBe(400);
 expect((await post('{"code":false}',{},'?code=query-cannot-hide-invalid-body')).status).toBe(400);
 expect((await post('{}',{},'?state=a&state=b')).status).toBe(400);
 expect((await post('{}',{'content-type':'text/plain'})).status).toBe(415);
 expect((await post('{}',{'cookie':'some-cookie=value',origin:'https://untrusted.example'})).status).toBe(403);
 expect((await post('{}',{'cookie':'some-cookie=value'})).status).toBe(403);
 const allowed=await post('{"code":"body","state":"s +&=é","unknown":{"discard":true}}',{origin:'https://provider.example','sec-fetch-site':'cross-site'},'?code=query');
 expect(allowed.status).toBe(302);expect(allowed.headers.get('cache-control')).toBe('no-store');expect(allowed.headers.getSetCookie()).toEqual([]);
 const redirect=new URL(allowed.headers.get('location')!);expect(redirect.origin+redirect.pathname).toBe(target);expect([...redirect.searchParams]).toEqual([['code','query'],['state','s +&=é']]);
 expect((await post('{}',{'cookie':'some-cookie=value',origin:'http://localhost:3000'})).status).toBe(302);
 const schema=await ready.auth.api.generateOpenAPISchema();const callback=schema.paths['/callback/{id}'];
 expect(callback.post.responses['302']).toBeDefined();expect(callback.post.requestBody.required).toBe(false);
 expect(callback.post.requestBody.content['application/x-www-form-urlencoded'].schema.properties.state).toEqual({type:'string'});
 expect(callback.post.requestBody.content['application/json'].schema).toEqual(callback.post.requestBody.content['application/x-www-form-urlencoded'].schema);
});
