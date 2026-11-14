/** Isolated loopback HTTPS development entrypoint. Not part of Next.js routes/build.
 * Reuses existing gateway modules; never loads dotenv or selects a production IP provider.
 */
import { readFileSync, lstatSync, existsSync, realpathSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { Script } from 'node:vm';
import * as crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { isIP } from 'node:net';
import https from 'node:https';
import http from 'node:http';
import { Readable } from 'node:stream';

export const POLICY = 'local-loopback-development-v1';
const ORIGIN = 'https://localhost:3443';
const BACKEND = 'http://127.0.0.1:8001';

export function requireLocal(environment = process.env) {
  if (environment.NODE_ENV !== 'development' || ['VERCEL', 'RAILWAY_ENVIRONMENT_ID', 'RENDER'].some(k => environment[k])) {
    throw new Error('Local development only.');
  }
}

export function profileAt(state) {
  if (lstatSync(state).isSymbolicLink()) throw new Error('Local state cannot be a symlink.');
  state = realpathSync(state);
  for (let parent = resolve(state); ; parent = dirname(parent)) {
    if ((existsSync(parent) && lstatSync(parent).isSymbolicLink()) || existsSync(join(parent, '.git'))) throw new Error('Local state must be outside repositories.');
    if (dirname(parent) === parent) break;
  }
  for (const path of [state, join(state, 'profile.json')]) {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077)) throw new Error('Private local state required.');
  }
  const value = JSON.parse(readFileSync(join(state, 'profile.json'), 'utf8'));
  const roles = ['staging', 'issuance', 'chat', 'signing', 'ip_key'];
  if (value.version !== 1 || Object.keys(value).sort().join() !== ['version', ...roles].sort().join()) throw new Error('Invalid local profile.');
  const secrets = roles.map(k => value[k]);
  if (new Set(secrets).size !== roles.length || secrets.some(v => typeof v !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(v) || Buffer.from(v, 'base64url').toString('base64url') !== v)) throw new Error('Invalid local credentials.');
  return value;
}

export function loadModules(frontend) {
  // Compile only the four reviewed SERVER modules, using the already-installed
  // project compiler. No dependency installation, env-file loader or Next build.
  const compiler = createRequire(join(frontend, 'package.json'))('typescript');
  const names = new Set(['session-gateway', 'chat-gateway', 'visitor-identity', 'gateway-assertions']);
  const cache = new Map();
  const natives = { 'server-only': {}, 'node:crypto': crypto, 'node:buffer': { Buffer },
    'node:net': { isIP }, 'node:url': { URL } };
  function load(name) {
    if (!names.has(name)) throw new Error('Unsupported development module.');
    if (cache.has(name)) return cache.get(name);
    const source = readFileSync(join(frontend, 'src/lib/server', name + '.ts'), 'utf8');
    const compiled = compiler.transpileModule(source, { reportDiagnostics: true,
      compilerOptions: { module: compiler.ModuleKind.CommonJS, target: compiler.ScriptTarget.ES2022 } });
    if (compiled.diagnostics?.some(d => d.category === compiler.DiagnosticCategory.Error)) throw new Error('Server module compilation failed.');
    // server-only is satisfied by this dedicated Node server, not browser code.
    // The loader offers no filesystem, process environment or arbitrary imports.
    const result = new Script(`(() => {const exports = {}; ${compiled.outputText}\nreturn exports;})()`)
      .runInNewContext({ Request, Response, Headers, URL, Buffer, Uint8Array, TextDecoder, TextEncoder,
        AbortController, performance, setTimeout, clearTimeout,
        require(dependency) {
          if (Object.hasOwn(natives, dependency)) return natives[dependency];
          if (dependency.startsWith('./')) return load(dependency.slice(2));
          throw new Error('Unsupported development dependency.');
        } });
    cache.set(name, result);
    return result;
  }
  return { chat: load('chat-gateway'), session: load('session-gateway'), identity: load('visitor-identity') };
}

export function localHandlers(modules, profile, address, fetchImplementation = fetch) {
  requireLocal();
  if (address !== '127.0.0.1') throw new Error('Loopback peer required.');
  class SocketIdentity extends modules.identity.TrustedVisitorIdentityProvider {
    constructor() { super(POLICY); }
    async resolveEvidence(context) {
      return { visitorIP: address, ingressPolicy: POLICY, requestId: context.requestId,
        evidenceId: crypto.randomUUID() };
    }
  }
  const common = { APP_ORIGIN: ORIGIN, AI_ASSISTANT_BACKEND_URL: BACKEND,
    AI_ASSISTANT_BACKEND_TOKEN: profile.issuance };
  const scopedFetch = (url, init) => {
    const target = new URL(url);
    if (target.origin !== BACKEND || !['/internal/session-chat', '/internal/verified-sessions'].includes(target.pathname)
        || target.search || target.hash || init.method !== 'POST') throw new Error('Invalid local upstream.');
    return fetchImplementation(url, init);
  };
  return {
    session: modules.session.createSessionGateway({ readEnvironment: () => ({ ...common, CHAT_SESSION_ENABLED: 'true' }), fetch: scopedFetch }),
    chat: modules.chat.createChatGateway({ readEnvironment: () => ({ ...common, CHAT_ENABLED: 'true',
      AI_ASSISTANT_CHAT_TOKEN: profile.chat, GATEWAY_ASSERTION_ISSUER: 'portfolio-local-gateway',
      GATEWAY_ASSERTION_AUDIENCE: 'portfolio-local-backend', GATEWAY_ASSERTION_KEY_ID: 'local-key-1',
      GATEWAY_ASSERTION_KEY: profile.signing, GATEWAY_ASSERTION_KEY_NOT_BEFORE: '0',
      GATEWAY_ASSERTION_KEY_NOT_AFTER: '253402300799', GATEWAY_INGRESS_POLICY: POLICY }),
      identityProvider: new SocketIdentity(), fetch: scopedFetch }),
  };
}

// Only Next's development HMR protocol may upgrade. This is not a generic
// WebSocket proxy and never attaches chat credentials or forwards browser cookies.
export function hmrHeaders(req) {
  if (req.socket.remoteAddress !== '127.0.0.1' || req.method !== 'GET' ||
      typeof req.url !== 'string' || req.url.length > 256 ||
      /^\/_next\/hmr(?:\?id=[A-Za-z0-9_-]{1,128})?$/.exec(req.url)?.[0] !== req.url ||
      !Array.isArray(req.rawHeaders) || req.rawHeaders.length > 64) throw new Error('HMR unavailable.');
  const values = name => req.rawHeaders.reduce((all, value, i, raw) => {
    if (i % 2 === 0 && typeof value === 'string' && value.toLowerCase() === name) all.push(raw[i+1]);
    return all;
  }, []);
  const one = name => {
    const result = values(name);
    if (result.length !== 1 || typeof result[0] !== 'string' || /[\r\n\0]/.test(result[0])) throw new Error('HMR unavailable.');
    return result[0];
  };
  if (one('host') !== 'localhost:3443' || one('origin') !== ORIGIN ||
      one('upgrade').toLowerCase() !== 'websocket' || one('sec-websocket-version') !== '13' ||
      !one('connection').split(',').some(token => token.trim().toLowerCase() === 'upgrade') ||
      values('content-length').length || values('transfer-encoding').length || values('sec-websocket-protocol').length) {
    throw new Error('HMR unavailable.');
  }
  const key = one('sec-websocket-key');
  if (Buffer.from(key, 'base64').length !== 16 || Buffer.from(key, 'base64').toString('base64') !== key) throw new Error('HMR unavailable.');
  const headers = { Host: 'localhost:3443', Origin: ORIGIN, Connection: 'Upgrade', Upgrade: 'websocket',
    'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key };
  if (values('sec-websocket-extensions').length) headers['Sec-WebSocket-Extensions'] = one('sec-websocket-extensions');
  return headers;
}

export function attachHmrProxy(server, { request = http.request, maxConnections = 8, handshakeMs = 5000 } = {}) {
  requireLocal();
  if (!Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 8 ||
      !Number.isInteger(handshakeMs) || handshakeMs < 1 || handshakeMs > 5000) throw new Error('Invalid HMR limits.');
  const active = new Set();
  const upgrade = (req, client, clientHead) => {
    let headers;
    try { headers = hmrHeaders(req); } catch { client.destroy(); return; }
    if (active.size >= maxConnections) { client.destroy(); return; }
    let upstream, peer, timer, closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      active.delete(cleanup);
      upstream?.destroy();
      peer?.destroy();
      client.destroy();
    };
    active.add(cleanup);
    client.once('error', cleanup);
    client.once('close', cleanup);
    client.once('end', cleanup);
    timer = setTimeout(cleanup, handshakeMs);
    try {
      upstream = request({ hostname: '127.0.0.1', port: 3000, method: 'GET', path: req.url, headers });
      upstream.once('error', cleanup);
      upstream.once('close', () => { if (!peer) cleanup(); });
      upstream.once('response', response => { response.destroy(); cleanup(); });
      upstream.once('upgrade', (response, socket, serverHead) => {
        peer = socket;
        if (closed) { socket.destroy(); return; }
        const expected = crypto.createHash('sha1').update(headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
        if (response.statusCode !== 101 || response.headers.upgrade?.toLowerCase() !== 'websocket' ||
            !response.headers.connection?.toLowerCase().split(',').some(token => token.trim() === 'upgrade') ||
            response.headers['sec-websocket-accept'] !== expected || response.headers['sec-websocket-protocol']) {
          cleanup(); return;
        }
        clearTimeout(timer);
        peer.once('error', cleanup);
        peer.once('close', cleanup);
        peer.once('end', cleanup);
        const handshake = ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade',
          'Sec-WebSocket-Accept: ' + expected];
        const extensions = response.headers['sec-websocket-extensions'];
        if (extensions !== undefined) {
          if (typeof extensions !== 'string' || /[\r\n\0]/.test(extensions)) { cleanup(); return; }
          handshake.push('Sec-WebSocket-Extensions: ' + extensions);
        }
        client.write(handshake.join('\r\n') + '\r\n\r\n');
        if (serverHead.length) client.write(serverHead);
        if (clientHead.length) peer.write(clientHead);
        client.pipe(peer);
        peer.pipe(client);
      });
      upstream.end();
    } catch { cleanup(); }
  };
  server.on('upgrade', upgrade);
  const close = () => { for (const cleanup of active) cleanup(); };
  server.once('close', close);
  return close;
}

export async function start(frontend, state) {
  requireLocal();
  const profile = profileAt(state), modules = loadModules(frontend);
  const keyPath = join(state, 'localhost.key');
  const info = lstatSync(keyPath);
  if (info.isSymbolicLink() || info.uid !== process.getuid() || info.mode & 0o077) throw new Error('Private TLS key required.');
  const server = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(join(state, 'localhost.crt')),
    maxHeaderSize: 8192, minVersion: 'TLSv1.2' }, async (req, res) => {
    const deny = status => { res.writeHead(status, { 'Cache-Control': 'no-store' }); res.end('Local request unavailable.'); };
    try {
      if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== 'localhost:3443' || req.rawHeaders.length > 64) return deny(403);
      if (req.url === '/api/chat' || req.url === '/api/chat/session') {
        const headers = new Headers();
        for (let i = 0; i < req.rawHeaders.length; i += 2) headers.append(req.rawHeaders[i], req.rawHeaders[i+1]);
        const controller = new AbortController();
        req.on('aborted', () => controller.abort());
        res.on('close', () => { if (!res.writableEnded) controller.abort(); });
        const request = new Request(ORIGIN + req.url, { method: req.method, headers, signal: controller.signal,
          ...(!['GET','HEAD'].includes(req.method) ? { body: Readable.toWeb(req), duplex: 'half' } : {}) });
        const handlers = localHandlers(modules, profile, req.socket.remoteAddress);
        const result = await (req.url === '/api/chat' ? handlers.chat : handlers.session)(request);
        res.writeHead(result.status, Object.fromEntries(result.headers));
        res.end(Buffer.from(await result.arrayBuffer()));
      } else if (req.url.startsWith('/api/')) {
        deny(404);
      } else {
        // UI/assets only, streamed to the separate existing Next dev server.
        // No gateway credentials are attached. HMR has its own restricted upgrade handler.
        const upstream = http.request({ hostname: '127.0.0.1', port: 3000, path: req.url,
          method: req.method, headers: req.headers, timeout: 50000 }, incoming => {
          res.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(res);
        });
        upstream.on('timeout', () => upstream.destroy());
        upstream.on('error', () => { if (!res.headersSent) deny(502); else res.destroy(); });
        req.on('aborted', () => upstream.destroy());
        req.pipe(upstream);
      }
    } catch { if (!res.headersSent) deny(503); else res.destroy(); }
  });
  server.requestTimeout = 55000;
  server.headersTimeout = 5000;
  server.maxConnections = 32;
  attachHmrProxy(server);
  server.listen(3443, '127.0.0.1', () => console.log('Local HTTPS gateway: https://localhost:3443 (loopback only)'));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [frontend, state] = process.argv.slice(2);
  if (!frontend || !state) { console.error('Usage: NODE_ENV=development node scripts/local_frontend.mjs FRONTEND STATE'); process.exitCode=1; }
  else await start(resolve(frontend), resolve(state)).catch(() => {
    console.error('Local HTTPS runner unavailable. Check paths, private configuration, certificate and ports.'); process.exitCode=1;
  });
}
