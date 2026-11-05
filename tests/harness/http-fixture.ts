import {createServer} from 'node:http';
import {once} from 'node:events';
import {afterAll} from 'vitest';

const servers = new Set<ReturnType<typeof createServer>>();
afterAll(async () => {
 await Promise.all([...servers].map(server => new Promise<void>((resolve,reject) => {
  server.close(error => error ? reject(error) : resolve());
  server.closeAllConnections();
 })));
 servers.clear();
});

// Bytes and HTTP headers only. Routing, authentication, authorization, callbacks
// and persistence still execute through the native V fixture.
export async function nativeHTTP() {
 let handler: ((request:Request)=>Promise<Response>) | undefined;
 const server=createServer(async (incoming,outgoing)=>{
  try {
   const chunks:Buffer[]=[];
   for await(const chunk of incoming) chunks.push(Buffer.from(chunk));
   const headers=new Headers();
   for(let i=0;i<incoming.rawHeaders.length;i+=2) headers.append(incoming.rawHeaders[i],incoming.rawHeaders[i+1]);
   const method=incoming.method??'GET';
   const body=Buffer.concat(chunks);
   const request=new Request(origin+(incoming.url??'/'),{method,headers,...(method==='GET'||method==='HEAD'?{}:{body})});
   const response=handler ? await handler(request) : new Response('Native handler not installed',{status:503});
   outgoing.statusCode=response.status;
   for(const [name,value] of response.headers) if(name!=='set-cookie') outgoing.setHeader(name,value);
   const cookies=response.headers.getSetCookie();
   if(cookies.length) outgoing.setHeader('set-cookie',cookies);
   outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
   outgoing.statusCode=500;outgoing.end('HTTP fixture failed');
  }
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');servers.add(server);
 const origin='http://127.0.0.1:'+(server.address() as {port:number}).port;
 return {origin,install(auth:{handler(request:Request):Promise<Response>}){handler=request=>auth.handler(request)}};
}
