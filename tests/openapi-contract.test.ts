import {it,expect,vi} from 'vitest';
import {openAPI} from 'better-auth/plugins';
import {organization} from './harness/plugins.js';
import {createAuthEndpoint} from './harness/endpoint.js';
import {getTestInstance} from './harness/test-instance.js';
it('generates native model/core/plugin documentation without exposing runtime credentials or invoking handlers',async()=>{
 const handler=vi.fn(async()=>({ok:true}));
 const plugin={id:'documentation-contract',endpoints:{
  first:createAuthEndpoint('/custom/a',{method:'GET',metadata:{openapi:{operationId:'custom',description:'First native operation',responses:{200:{description:'Custom success'}}}}},handler),
  second:createAuthEndpoint('/custom/b',{method:'GET',metadata:{openapi:{operationId:'custom'}}},handler),
  hidden:createAuthEndpoint('/custom/hidden',{method:'GET',metadata:{scope:'server'}},handler),
 }};
 const secret='openapi-must-not-publish-this-instance-secret';
 const ready=await getTestInstance({secret,plugins:[openAPI(),organization(),plugin],user:{additionalFields:{review:{type:'string',input:false,defaultValue:'pending'},hidden:{type:'string',required:true,returned:false,defaultValue:'internal'}}}});
 const schema=await ready.auth.api.generateOpenAPISchema();expect(schema.openapi).toBe('3.1.1');expect(schema.servers).toEqual([{url:'http://localhost:3000/api/auth'}]);
 expect(schema.components.schemas.User.properties.review).toEqual({type:'string',readOnly:true,default:'pending'});expect(schema.components.schemas.User.required).not.toContain('hidden');
 expect(schema.paths['/sign-up/email'].post.requestBody.content['application/json'].schema.properties.review).toBeUndefined();
 expect(schema.components.schemas.Organization).toBeDefined();expect(schema.components.schemas.Member).toBeDefined();expect(schema.components.schemas.OrganizationRole).toBeDefined();
 expect(schema.paths['/organization/invite-member'].post).toBeDefined();expect(schema.paths['/internal/organization/add-member']).toBeUndefined();expect(schema.paths['/reference']).toBeUndefined();expect(schema.paths['/custom/hidden']).toBeUndefined();
 expect(schema.paths['/custom/a'].get).toMatchObject({operationId:'custom',description:'First native operation',responses:{200:{description:'Custom success'}}});expect(schema.paths['/custom/b'].get.operationId).not.toBe('custom');
 expect(handler).not.toHaveBeenCalled();expect(JSON.stringify(schema)).not.toContain(secret);expect(JSON.stringify(schema)).not.toContain(ready.testUser.email);
 const response=await ready.auth.handler(new Request('http://localhost:3000/api/auth/open-api/generate-schema'));expect(response.status).toBe(200);expect(response.headers.get('content-type')).toContain('application/json');expect(await response.json()).toEqual(schema);
});
it('escapes embedded schemas, Scalar settings and CSP nonce attributes while preserving their values',async()=>{
 const value='x</script><img src=x onerror=alert(1)>&';const nonce='nonce" onload="evil';
 const ready=await getTestInstance({plugins:[openAPI({path:'/auth-docs',theme:value as any,nonce})],user:{additionalFields:{note:{type:'string',defaultValue:value}}}});
 const response=await ready.auth.api.openAPIReference({asResponse:true});expect(response.status).toBe(200);expect(response.headers.get('content-type')).toContain('text/html');const html=await response.text();
 expect(html).not.toContain(value);expect(html).not.toContain('<img');expect(html.match(/<\/script>/g)).toHaveLength(3);expect(html).toContain('nonce="nonce&quot; onload=&quot;evil"');
 const embedded=html.match(/<script id="api-reference" type="application\/json">([\s\S]*?)<\/script>/);expect(embedded).not.toBeNull();expect(JSON.parse(embedded![1]).components.schemas.User.properties.note.default).toBe(value);
 const setting=html.match(/dataset\.configuration=([\s\S]*?);<\/script>/);expect(setting).not.toBeNull();expect(JSON.parse(JSON.parse(setting![1]))).toEqual({theme:value});
 expect(html).toContain('https://cdn.jsdelivr.net/npm/@scalar/api-reference');
});
it('disables only the reference endpoint when configured',async()=>{
 const ready=await getTestInstance({plugins:[openAPI({disableDefaultReference:true})]});
 expect((await ready.auth.handler(new Request('http://localhost:3000/api/auth/reference'))).status).toBe(404);
 expect((await ready.auth.handler(new Request('http://localhost:3000/api/auth/open-api/generate-schema'))).status).toBe(200);
});


import {emailOTP} from './harness/plugins.js';
it('documents native email OTP requests and accepts the documented sign-in fields',async()=>{
 const delivered:any[]=[];
 const ready=await getTestInstance({plugins:[openAPI(),emailOTP({sendVerificationOTP:async data=>{delivered.push(data)}})],user:{additionalFields:{tag:{type:'string',required:false}}}},{disableTestUser:true});
 const schema=await ready.auth.api.generateOpenAPISchema();expect(delivered).toEqual([]);
 const bodyFor=(path:string)=>schema.paths[path].post.requestBody.content['application/json'].schema;
 expect(bodyFor('/email-otp/send-verification-otp').required).toEqual(['email','type']);expect(bodyFor('/email-otp/send-verification-otp').properties.type.enum).toEqual(['email-verification','sign-in','forget-password']);
 expect(bodyFor('/email-otp/request-email-change').required).toEqual(['newEmail']);expect(bodyFor('/email-otp/change-email').required).toEqual(['newEmail','otp']);
 expect(bodyFor('/email-otp/check-verification-otp').required).toEqual(['email','type','otp']);expect(schema.paths['/forget-password/email-otp'].post.deprecated).toBe(true);
 expect(schema.paths['/email-otp/create-verification-otp']).toBeUndefined();expect(schema.paths['/email-otp/get-verification-otp']).toBeUndefined();
 const email='documented@example.com';await ready.auth.api.sendVerificationOTP({body:{email,type:'sign-in'}});expect(delivered).toHaveLength(1);
 const result=await ready.auth.api.signInEmailOTP({body:{email,otp:delivered[0].otp,name:'Documented',tag:'native-data'}});expect(result.user).toMatchObject({email,emailVerified:true,tag:'native-data'});
 const session=await ready.auth.api.getSession({headers:{authorization:`Bearer ${result.token}`}});expect(session?.user.id).toBe(result.user.id);
});
