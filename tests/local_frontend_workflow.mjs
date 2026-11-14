/** Offline browser transport -> existing gateways -> Python ASGI pipe bridge. */
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Script } from 'node:vm';
import net from 'node:net';
import dns from 'node:dns';
import { loadModules, localHandlers } from '../scripts/local_frontend.mjs';
const blocked = () => { throw new Error('Offline test: network disabled'); };
net.Socket.prototype.connect = blocked;
dns.lookup = blocked;
globalThis.fetch = blocked;
const lines = createInterface({ input: process.stdin });
const iterator = lines[Symbol.asyncIterator]();
const input = JSON.parse((await iterator.next()).value);
let calls = 0, sessionStatus, chatStatus, cookie;
const fetchMock = async (url, init) => {
  calls++;
  console.log(JSON.stringify({ request: { url, method: init.method,
    headers: Object.fromEntries(new Headers(init.headers)), body: Buffer.from(init.body).toString('utf8') } }));
  const value = JSON.parse((await iterator.next()).value);
  return new Response(JSON.stringify(value.body), { status: value.status, headers: { 'Content-Type': 'application/json' } });
};
try {
  const handlers = localHandlers(loadModules(input.frontend), input.profile, '127.0.0.1', fetchMock);
  const browserFetch = async (path, init) => {
    if (!['/api/chat','/api/chat/session'].includes(path) || init.credentials !== 'same-origin') throw new Error();
    const headers = { ...init.headers, Origin: 'https://localhost:3443', 'Sec-Fetch-Site': 'same-origin',
      ...(cookie ? { Cookie: cookie.split(';')[0] } : {}) };
    const request = new Request('https://localhost:3443'+path, { ...init, headers });
    const response = await (path === '/api/chat/session' ? handlers.session : handlers.chat)(request);
    if (path === '/api/chat/session') {
      sessionStatus = response.status;
      if (response.status === 201) {
        cookie = response.headers.get('set-cookie');
        const json = await response.clone().json();
        if (!cookie?.includes('Secure') || !cookie.includes('HttpOnly') || !cookie.includes('SameSite=Strict') ||
            !cookie.includes('Path=/') || /Domain=/i.test(cookie) || JSON.stringify(json).includes('token')) throw new Error();
      }
    } else chatStatus=response.status;
    return response;
  };
  const ts = createRequire(input.frontend+'/package.json')('typescript');
  const source = readFileSync(input.frontend+'/src/lib/assistant-client.ts','utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } });
  const browser = new Script(`(() => {const exports={}; ${compiled.outputText}\nreturn exports;})()`)
    .runInNewContext({ fetch: browserFetch });
  try {
    const signal = new AbortController().signal;
    // The mock challenge proof replaces only the external browser widget.
    await browser.requestVerifiedSession(input.proof ?? 'offline-proof-only', signal);
    const answer = await browser.requestAssistantAnswer('What is BundesHost?', signal);
    console.log(JSON.stringify({ done:true,sessionStatus,chatStatus,body:{answer},secureCookie:true,calls }));
  } catch (error) {
    if (typeof error.status !== 'number') throw error;
    console.log(JSON.stringify({ done:true,sessionStatus,chatStatus,calls }));
  }
} catch {
  console.log(JSON.stringify({ done:true,error:'Offline gateway workflow failed.' }));process.exitCode=1;
} finally { lines.close(); }
