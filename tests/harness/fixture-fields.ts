import {recordMetadata} from "./bridge.js";
import type {FixtureOptions} from "./fixture-types.js";

export function hydrateFixture(value:any,modelHint:string,fieldSchemas:Record<string,Record<string,FixtureOptions>>,adapterModels:Record<string,unknown>):any {
   if(value instanceof Date)return value;
   if(Array.isArray(value))return value.map(item=>hydrateFixture(item,modelHint,fieldSchemas,adapterModels));
   if(!value||typeof value!=='object')return value;
   const model=modelHint||('email' in value&&'name' in value&&'emailVerified' in value?'user':'userId' in value&&'token' in value&&'expiresAt' in value?'session':'organizationId' in value?('inviterId' in value?'invitation':'userId' in value?'member':'permission' in value?'organizationRole':''):'slug' in value&&'name' in value?'organization':'');
   const schema=fieldSchemas[model]??{};
   const result=Object.fromEntries(Object.entries(value).filter(([name])=>name!=='$vSession').map(([name,item])=>{
    if(schema[name]?.type==='json'||model==='organization'&&name==='metadata')return [name,item];
    if(typeof item==='string'&&(schema[name]?.type==='date'||['createdAt','updatedAt','expiresAt','accessTokenExpiresAt','refreshTokenExpiresAt'].includes(name)))return [name,new Date(item)];
    return [name,hydrateFixture(item,adapterModels[name]?name:'',fieldSchemas,adapterModels)];
   }));
   if(value.$vSession)Object.defineProperty(result,recordMetadata,{value:value.$vSession});
   return result;
  }

export function registerFieldCallbacks(schemas:Record<string,Record<string,FixtureOptions>>,callbacks:Record<string,(payload:any)=>unknown>){
  const fieldCallbackNames: string[] = [];
  const fieldValue = (value: unknown) => ({value: value ?? null, undefinedValue: value === undefined});
  for (const [model,fields] of Object.entries(schemas)) {
   for (const [name, field] of Object.entries(fields) as Array<[string,FixtureOptions]>) {
    if(typeof field.defaultValue==='function'){
     const method='field.'+model+'.'+name+'.default';fieldCallbackNames.push(method);
     callbacks[method]=()=>{const value=field.defaultValue();if(value instanceof Promise){void value.catch(()=>undefined);return {...fieldValue(undefined),asynchronous:true}}return fieldValue(value)};
    }
    if (field.validator?.input) {
     const method = 'field.'+model+'.'+name+'.validate'; fieldCallbackNames.push(method);
     callbacks[method] = value => {
      const result = field.validator.input['~standard'].validate(value);
      if (result instanceof Promise) {void result.catch(()=>undefined);return {...fieldValue(undefined),asynchronous:true};}
      return {...fieldValue(result.value),invalid:!!result.issues,message:result.issues?.[0]?.message ?? ''};
     };
    }
    if (field.transform?.input) {
     const method = 'field.'+model+'.'+name+'.transform'; fieldCallbackNames.push(method);
     callbacks[method] = async value => fieldValue(await field.transform.input(value));
    }
   }
  }
  return fieldCallbackNames;
}

export const encodeFields = (fields: FixtureOptions) => JSON.stringify(Object.fromEntries(Object.entries(fields).map(([name,field]:[string,FixtureOptions])=>{
   const {validator:_validator,transform:_transform,...metadata} = field;return [name,metadata];
  })));
