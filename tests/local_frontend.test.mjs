import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { requireLocal, localHandlers, profileAt, loadModules } from '../scripts/local_frontend.mjs';
const frontend='/Users/timothyajayi/PycharmProjects/ai-engineer-portfolio';
const modules=loadModules(frontend);
const profile={version:1,...Object.fromEntries(['staging','issuance','chat','signing','ip_key'].map(k=>[k,randomBytes(32).toString('base64url')]))};
test('hosted/production selection and missing opt-in fail closed',()=>{
  for(const environment of [{},{NODE_ENV:'production'},{NODE_ENV:'development',VERCEL:'1'},
    {NODE_ENV:'development',RAILWAY_ENVIRONMENT_ID:'test'}]) assert.throws(()=>requireLocal(environment));
  requireLocal({NODE_ENV:'development'});
});
test('socket identity requires exact bound loopback peer',()=>{
  process.env.NODE_ENV='development';
  for(const address of [null,'192.0.2.1','::1','127.0.0.2']) assert.throws(()=>localHandlers(modules,profile,address));
});
test('missing session, forged forwarding headers, bad origin cause no fetch',async()=>{
  process.env.NODE_ENV='development';let calls=0;
  const handlers=localHandlers(modules,profile,'127.0.0.1',()=>{calls++;throw Error();});
  for(const extra of [{},{'X-Forwarded-For':'127.0.0.1'},{Origin:'https://evil.example'}]){
    const response=await handlers.chat(new Request('https://localhost:3443/api/chat',{
      method:'POST',headers:{'Content-Type':'application/json',Origin:'https://localhost:3443',...extra},body:'{"message":"Hello"}'}));
    assert.notEqual(response.status,200);assert.equal(calls,0);
  }
});
test('private profile rejects loose permissions and equal credentials',()=>{
 const directory=mkdtempSync(join(tmpdir(),'local-profile-'));chmodSync(directory,0o700);
 try{
  const path=join(directory,'profile.json');writeFileSync(path,JSON.stringify(profile),{mode:0o600});
  assert.equal(profileAt(directory).version,1);
  chmodSync(path,0o644);assert.throws(()=>profileAt(directory));chmodSync(path,0o600);
  writeFileSync(path,JSON.stringify({...profile,chat:profile.issuance}));assert.throws(()=>profileAt(directory));
 }finally{rmSync(directory,{recursive:true});}
});

// Real production handler, injectable upstream transport; never a public proxy.
import { EventEmitter, once } from 'node:events';
import { createRequire } from 'node:module';
import { Duplex } from 'node:stream';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { hmrHeaders, attachHmrProxy } from '../scripts/local_frontend.mjs';

const websocketKey=Buffer.alloc(16,1).toString('base64');
function upgradeRequest(changes={}) {
  return { method:'GET',url:'/_next/hmr?id=next_request-01',socket:{remoteAddress:'127.0.0.1'},rawHeaders:[
    'Host','localhost:3443','Origin','https://localhost:3443','Connection','Upgrade','Upgrade','websocket',
    'Sec-WebSocket-Version','13','Sec-WebSocket-Key',websocketKey],...changes };
}
class Wire extends Duplex {
  output=[];
  _read() {}
  _write(chunk,_encoding,done) { this.output.push(Buffer.from(chunk));done(); }
}
function tunnel(options={}) {
  process.env.NODE_ENV='development';
  const server=new EventEmitter(),client=new Wire(),peer=new Wire();
  const upstream=new EventEmitter();upstream.end=()=>{};upstream.destroy=()=>{upstream.destroyed=true;};
  const calls=[];
  const close=attachHmrProxy(server,{request:args=>{calls.push(args);return upstream;},...options});
  return {server,client,peer,upstream,calls,close};
}
function response(changes={}) {
  return {statusCode:101,headers:{upgrade:'websocket',connection:'Upgrade',
    'sec-websocket-accept':createHash('sha1').update(websocketKey+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')},...changes};
}
test('HMR permits only canonical endpoint, optional request id and exact local authority',()=>{
  for(const url of ['/_next/hmr','/_next/hmr?id=next_request-01']) {
    assert.equal(hmrHeaders(upgradeRequest({url})).Origin,'https://localhost:3443');
  }
  for(const url of ['/api/chat','/internal/session-chat','/_next/hmr/','/_next//hmr','/%5fnext/hmr',
    '/_next/hmr?target=evil','/_next/hmr?id=a&id=b','/_next/hmr?id=a&x=1','/_next/hmr?id=',
    '/_next/hmr?id=x\n','/_next/hmr?id=x#bad','http://localhost:3443/_next/hmr']) {
    assert.throws(()=>hmrHeaders(upgradeRequest({url})),url);
  }
  for(const remoteAddress of ['192.0.2.1','::1','127.0.0.2']) {
    assert.throws(()=>hmrHeaders(upgradeRequest({socket:{remoteAddress}})));
  }
  assert.throws(()=>hmrHeaders(upgradeRequest({method:'POST'})));
});
test('HMR rejects wrong/missing/duplicate host, origin and handshake headers',()=>{
  const replacements={host:'evil.example',origin:'https://evil.example',connection:'keep-alive',
    upgrade:'h2c','sec-websocket-version':'12','sec-websocket-key':'bad'};
  for(const [name,value]of Object.entries(replacements)) {
    const request=upgradeRequest();const index=request.rawHeaders.findIndex(v=>v.toLowerCase()===name);
    const wrong=[...request.rawHeaders];wrong[index+1]=value;
    assert.throws(()=>hmrHeaders({...request,rawHeaders:wrong}));
    const missing=[...request.rawHeaders];missing.splice(index,2);
    assert.throws(()=>hmrHeaders({...request,rawHeaders:missing}));
    assert.throws(()=>hmrHeaders({...request,rawHeaders:[...request.rawHeaders,name,request.rawHeaders[index+1]]}));
  }
  for(const pair of [['Content-Length','0'],['Transfer-Encoding','chunked'],['Sec-WebSocket-Protocol','chat']]) {
    assert.throws(()=>hmrHeaders({...upgradeRequest(),rawHeaders:[...upgradeRequest().rawHeaders,...pair]}));
  }
});
test('HMR forwards fixed target, strips credentials and preserves handshake and both directions',async()=>{
  const t=tunnel();
  try {
    const req=upgradeRequest();req.rawHeaders.push('Cookie','PRIVATE-COOKIE','Authorization','Bearer PRIVATE',
      'X-Portfolio-Session','PRIVATE-SESSION','X-Forwarded-For','192.0.2.1');
    t.server.emit('upgrade',req,t.client,Buffer.from('early-client'));
    assert.equal(t.calls.length,1);
    assert.equal(t.calls[0].hostname,'127.0.0.1');assert.equal(t.calls[0].port,3000);
    assert.equal(t.calls[0].path,req.url);
    assert.ok(!JSON.stringify(t.calls).includes('PRIVATE'));
    assert.ok(!JSON.stringify(t.calls).includes('192.0.2.1'));
    t.upstream.emit('upgrade',response(),t.peer,Buffer.from('early-server'));
    t.client.push(Buffer.from('client-message'));t.peer.push(Buffer.from('server-message'));
    await new Promise(resolve=>setImmediate(resolve));
    const client=Buffer.concat(t.client.output).toString(),peer=Buffer.concat(t.peer.output).toString();
    assert.match(client,/HTTP\/1\.1 101 Switching Protocols/);
    assert.ok(client.includes('early-server')&&client.includes('server-message'));
    assert.ok(peer.includes('early-client')&&peer.includes('client-message'));
    t.client.destroy();await new Promise(resolve=>setImmediate(resolve));
    assert.ok(t.peer.destroyed&&t.upstream.destroyed);
  } finally {t.close();}
});
test('unauthorized upgrade never connects upstream',()=>{
 const t=tunnel();
 try {
  t.server.emit('upgrade',upgradeRequest({url:'/api/chat'}),t.client,Buffer.alloc(0));
  assert.equal(t.calls.length,0);assert.ok(t.client.destroyed);
 }finally{t.close();}
});
test('HMR enforces capacity and releases slots after failure',()=>{
 const t=tunnel({maxConnections:1}),second=new Wire(),third=new Wire();
 try{
  t.server.emit('upgrade',upgradeRequest(),t.client,Buffer.alloc(0));
  t.server.emit('upgrade',upgradeRequest(),second,Buffer.alloc(0));
  assert.equal(t.calls.length,1);assert.ok(second.destroyed);
  t.upstream.emit('error',new Error('PRIVATE upstream error'));
  assert.ok(t.client.destroyed);
  t.server.emit('upgrade',upgradeRequest(),third,Buffer.alloc(0));assert.equal(t.calls.length,2);
 }finally{t.close();second.destroy();third.destroy();}
});
test('HMR closes non-upgrades, invalid handshakes, peer failures and stalled handshakes',async()=>{
 for(const mode of ['response','invalid','peer-error','peer-end','upstream-close','client-close']){
  const t=tunnel();
  try{
   t.server.emit('upgrade',upgradeRequest(),t.client,Buffer.alloc(0));
   if(mode==='response')t.upstream.emit('response',{destroy(){}});
   else if(mode==='upstream-close')t.upstream.emit('close');
   else if(mode==='client-close'){t.client.destroy();await new Promise(r=>setImmediate(r));}
   else{
    t.upstream.emit('upgrade',response(mode==='invalid'?{statusCode:200}:{}),t.peer,Buffer.alloc(0));
    if(mode==='peer-error')t.peer.emit('error',new Error('PRIVATE'));
    if(mode==='peer-end')t.peer.emit('end');
   }
   assert.ok(t.client.destroyed&&t.upstream.destroyed,mode);
   if(['invalid','peer-error','peer-end'].includes(mode))assert.ok(t.peer.destroyed);
  }finally{t.close();}
 }
 const stalled=tunnel({handshakeMs:10});
 try{
  stalled.server.emit('upgrade',upgradeRequest(),stalled.client,Buffer.alloc(0));
  await new Promise(r=>setTimeout(r,25));assert.ok(stalled.client.destroyed&&stalled.upstream.destroyed);
 }finally{stalled.close();}
});
test('real HTTP upgrade handshake and framed WebSocket echo through HMR proxy',async()=>{
 process.env.NODE_ENV='development';
 const {WebSocket,WebSocketServer}=createRequire(join(frontend,'package.json'))('next/dist/compiled/ws');
 const wss=new WebSocketServer({noServer:true});
 const upstream=http.createServer();
 let receivedHeaders;
 upstream.on('upgrade',(req,socket,head)=>{
  receivedHeaders=req.headers;
  wss.handleUpgrade(req,socket,head,ws=>{ws.on('message',data=>ws.send('next:'+data));});
 });
 await new Promise(resolve=>upstream.listen(0,'127.0.0.1',resolve));
 const proxy=http.createServer();
 const closeTunnels=attachHmrProxy(proxy,{request:options=>{
  assert.equal(options.hostname,'127.0.0.1');assert.equal(options.port,3000);
  return http.request({...options,port:upstream.address().port});
 }});
 let ws;
 try{
  await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));
  ws=new WebSocket('ws://127.0.0.1:'+proxy.address().port+'/_next/hmr?id=next_request-01',{
    headers:{Host:'localhost:3443',Origin:'https://localhost:3443',Cookie:'PRIVATE',Authorization:'PRIVATE'}});
  await once(ws,'open');
  const result=once(ws,'message');ws.send('hello');
  assert.equal((await result)[0].toString(),'next:hello');
  assert.equal(receivedHeaders.cookie,undefined);assert.equal(receivedHeaders.authorization,undefined);
  assert.equal(receivedHeaders.origin,'https://localhost:3443');
 }finally{
  ws?.terminate();closeTunnels();for(const client of wss.clients)client.terminate();wss.close();
  await Promise.all([new Promise(resolve=>proxy.close(resolve)),new Promise(resolve=>upstream.close(resolve))]);
 }
});
