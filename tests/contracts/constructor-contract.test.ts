import {it,expect} from 'vitest';
import {betterAuth} from '../harness/constructor.js';
import {getTestInstance} from '../harness/test-instance.js';
import {bearer} from '../harness/plugins.js';
import {createAuthClient as createReactAuthClient} from 'better-auth/react';
import {inferAdditionalFields} from 'better-auth/client/plugins';
it('serves constructor API and HTTP calls through V with protected session fields',async()=>{
 const auth=betterAuth({baseURL:'http://localhost:3000',secret:'constructor-contract-secret-0123456789',plugins:[bearer()],emailAndPassword:{enabled:true},session:{additionalFields:{color:{type:'string',required:false},internalNote:{type:'string',input:false,defaultValue:'private'}}}});
 const created=await auth.api.signUpEmail({body:{name:'Constructor',email:'constructor@example.com',password:'password'}});
 const headers=new Headers({authorization:`Bearer ${created.token}`});
 expect((await auth.api.getSession({headers}))?.user.id).toBe(created.user.id);
 await auth.api.updateSession({headers,body:{color:'blue'}});
 expect((await auth.api.getSession({headers}))?.session.color).toBe('blue');
 const blocked=await auth.handler(new Request('http://localhost:3000/api/auth/update-session',{method:'POST',headers:{authorization:`Bearer ${created.token}`,origin:'http://localhost:3000','content-type':'application/json'},body:JSON.stringify({internalNote:'spoofed'})}));expect(blocked.status).toBe(400);
 expect((await auth.api.getSession({headers}))?.session.internalNote).toBe('private');
 await expect((auth.api as any).unsupportedEndpoint()).rejects.toThrow('Unported native constructor API');
 await expect((auth.api as any).constructor()).rejects.toThrow('Unported native constructor API');
 await expect((auth.api as any).__proto__()).rejects.toThrow('Unported native constructor API');
});
it('returns native additional fields through the official React client actions',async()=>{
 const ready=await getTestInstance({user:{additionalFields:{role:{type:'string',defaultValue:'member'},phone:{type:'string',required:false}}}});
 const client=createReactAuthClient({baseURL:'http://localhost:3000',plugins:[inferAdditionalFields({user:{role:{type:'string'},phone:{type:'string',required:false}}})],fetchOptions:{customFetchImpl:ready.customFetchImpl}});
 const result=await client.signIn.email({email:ready.testUser.email,password:ready.testUser.password});expect(result.error).toBeNull();expect(result.data?.user.role).toBe('member');expect(result.data?.user.phone).toBeNull();
});
