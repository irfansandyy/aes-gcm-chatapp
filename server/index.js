import express from 'express';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHmac } from 'node:crypto';
import { AsyncLocalStorage, createHook } from 'node:async_hooks';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';
import { ExpressPeerServer } from 'peer';
import { validateKey, randomId, randomAsciiKey, seal, encodeJson } from '../src/shared/crypto.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MAX_FRAME_BYTES = 80 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const ROOM_PATTERN = /^[a-f0-9]{64}$/;
const CLIENT_PATTERN = /^[a-f0-9]{32}$/;
const NONCE_PATTERN = /^[a-f0-9]{32,128}$/;

function normalizeIp(value = '') {
  const clean = String(value).trim().replace(/^::ffff:/, '');
  return clean === '::1' ? '127.0.0.1' : clean;
}

function integer(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function ascii(value, maximum, minimum = 1) {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum && /^[\x20-\x7e]*$/.test(value);
}

function readConfig(options) {
  const env = options.env ?? process.env;
  return {
    serverIp: normalizeIp(options.serverIp ?? env.PUBLIC_IP ?? ''),
    strictThreeIps: options.strictThreeIps ?? env.KDC_STRICT_THREE_IPS !== 'false',
    kdcKeysFile: options.kdcKeysFile ?? env.KDC_KEYS_FILE ?? '',
    trustProxy: options.trustProxy ?? env.TRUST_PROXY === 'true',
    maxClients: integer(options.maxClients ?? env.MAX_CLIENTS, 256, 2, 4096),
    maxRooms: integer(options.maxRooms ?? env.MAX_ROOMS, 128, 1, 2048),
    maxClientsPerIp: integer(options.maxClientsPerIp ?? env.MAX_CLIENTS_PER_IP, 12, 2, 128),
    turnPublicIp: options.turnPublicIp ?? env.TURN_PUBLIC_IP ?? '',
    turnSecretFile: options.turnSecretFile ?? env.TURN_SECRET_FILE ?? '',
    turnPort: integer(options.turnPort ?? env.TURN_PORT, 3478, 1, 65535),
    stunUrls: options.stunUrls ?? (env.STUN_URLS ? env.STUN_URLS.split(',').map((url) => url.trim()).filter(Boolean) : []),
    staticDir: path.resolve(ROOT, options.staticDir ?? env.STATIC_DIR ?? '.'),
    heartbeatMs: options.heartbeatMs ?? 20_000,
    frameRate: integer(options.frameRate ?? env.SOCKET_FRAME_RATE, 2000, 10, 5000),
    sessionTtlMs: options.sessionTtlMs ?? 15 * 60_000,
    peerEnabled: options.peerEnabled !== false,
    peerServerFactory: options.peerServerFactory ?? ExpressPeerServer,
  };
}

export function createAppServer(options = {}) {
  const config = readConfig(options);
  const app = express();
  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES, perMessageDeflate: false });
  const rooms = new Map();
  const clients = new Map();
  const rateBuckets = new Map();
  const nonceCache = new Map();
  let peerWss;
  let closing = false;
  const peerTimerScope = new AsyncLocalStorage();
  const peerTimers = new Map();
  const peerTimerHook = createHook({
    init(id, type, _trigger, resource) { if (type === 'Timeout' && peerTimerScope.getStore()) peerTimers.set(id, resource); },
    destroy(id) { peerTimers.delete(id); },
  });
  if (config.peerEnabled) peerTimerHook.enable();

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy ? 1 : false);
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' ws:; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    });
    next();
  });
  app.use(express.json({ limit: '8kb', strict: true }));

  function serverIp(req) {
    return config.serverIp || normalizeIp(req.socket.localAddress);
  }

  function requestIp(req) {
    if (config.trustProxy) {
      const parts = String(req.headers['x-forwarded-for'] ?? '').split(',').map(normalizeIp);
      const candidate = parts.at(-1);
      if (candidate && isIP(candidate)) return candidate;
    }
    return normalizeIp(req.socket.remoteAddress);
  }

  function takeRate(key, limit, windowMs = 60_000) {
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.until <= now) {
      if (rateBuckets.size >= 4096 && !rateBuckets.has(key)) return false;
      bucket = { count: 0, until: now + windowMs };
      rateBuckets.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count <= limit;
  }

  function send(socket, data) {
    if (socket.readyState !== WebSocket.OPEN) return;
    if (socket.bufferedAmount > 2 * 1024 * 1024) {
      socket.close(1013, 'Receiver is too slow. Reconnect to continue.');
      return;
    }
    socket.send(JSON.stringify(data));
  }

  function participants(room) {
    return [...room.clients.values()].map(({ clientId, peerId, identity, ip, role }) => ({ clientId, peerId, identity, ip, role }));
  }

  function broadcastPresence(room) {
    const list = participants(room);
    for (const member of room.clients.values()) send(member.socket, { type: 'presence', participants: list, serverIp: room.serverIp });
  }

  function leave(socket) {
    const member = socket.member;
    if (!member) return;
    socket.member = null;
    if (clients.get(member.clientId)?.socket !== socket) return;
    clients.delete(member.clientId);
    const room = rooms.get(member.roomId);
    if (room?.clients.get(member.clientId)?.socket !== socket) return;
    room.clients.delete(member.clientId);
    if (room.clients.size === 0) rooms.delete(member.roomId);
    else broadcastPresence(room);
  }

  function reject(socket, error) {
    send(socket, { type: 'error', error });
  }

  function join(socket, req, message) {
    if (socket.member) return reject(socket, 'Leave the current room before joining another room.');
    const { room: roomId, mode, clientId, peerId, identity, role = null, keyMode = 'shared', resumeToken = null } = message;
    if (!ROOM_PATTERN.test(roomId ?? '') || !CLIENT_PATTERN.test(clientId ?? '') || !ascii(peerId, 100)
      || !ascii(identity, 32) || !['relay', 'p2p'].includes(mode) || !['shared', 'kdc'].includes(keyMode)
      || (keyMode === 'kdc' ? !['Alice', 'Bob'].includes(role) : role !== null)
      || (resumeToken !== null && !CLIENT_PATTERN.test(resumeToken))) {
      return reject(socket, 'Invalid room registration. Use a room hash, a client identifier, and an ASCII display name.');
    }
    if (!takeRate(`join:${socket.ip}`, 30)) return reject(socket, 'Too many join attempts. Try again in a minute.');
    const existing = clients.get(clientId);
    const canResume = existing && resumeToken !== null && existing.resumeToken === resumeToken
      && existing.ip === socket.ip && existing.roomId === roomId && existing.role === role;
    if (existing && !canResume) return reject(socket, 'This client identifier is already connected.');
    if (!canResume && clients.size >= config.maxClients) return reject(socket, 'The server has reached its connection limit.');
    if (!canResume && [...clients.values()].filter((member) => member.ip === socket.ip).length >= config.maxClientsPerIp) return reject(socket, 'This IP address has reached its connection limit.');
    let room = rooms.get(roomId);
    if (!room) {
      if (rooms.size >= config.maxRooms) return reject(socket, 'The server has reached its room limit.');
      room = { mode, keyMode, clients: new Map(), serverIp: serverIp(req) };
      rooms.set(roomId, room);
    }
    if (room.mode !== mode || room.keyMode !== keyMode) return reject(socket, 'This room uses a different transport or key method.');
    if (!canResume && room.clients.size >= (mode === 'p2p' || keyMode === 'kdc' ? 2 : 32)) return reject(socket, 'This room is full.');
    if ([...room.clients.values()].some((entry) => entry.clientId !== clientId && entry.peerId === peerId)) return reject(socket, 'This peer identifier is already in use.');
    if (keyMode === 'kdc' && [...room.clients.values()].some((entry) => entry.clientId !== clientId && entry.role === role)) return reject(socket, `${role} is already connected in this room.`);
    const member = { clientId, peerId, identity, role, ip: socket.ip, socket, roomId, resumeToken };
    socket.member = member;
    room.clients.set(clientId, member);
    clients.set(clientId, member);
    if (canResume) {
      existing.socket.member = null;
      existing.socket.close(1000, 'This connection was resumed by the same client.');
    }
    send(socket, { type: 'joined', clientId, ip: socket.ip, serverIp: room.serverIp, mode, keyMode, participants: participants(room) });
    broadcastPresence(room);
  }

  wss.on('connection', (socket, req) => {
    socket.ip = requestIp(req);
    socket.alive = true;
    socket.frameTokens = config.frameRate;
    socket.frameRefilledAt = Date.now();
    socket.on('error', () => {});
    socket.on('pong', () => { socket.alive = true; });
    socket.on('close', () => leave(socket));
    const joinTimeout = setTimeout(() => { if (!socket.member) socket.close(1008, 'Join a room within 15 seconds.'); }, 15_000);
    joinTimeout.unref();
    socket.on('close', () => clearTimeout(joinTimeout));
    socket.on('message', (data, binary) => {
      if (binary) return reject(socket, 'Only JSON frames are supported.');
      const now = Date.now();
      socket.frameTokens = Math.min(config.frameRate, socket.frameTokens + (now - socket.frameRefilledAt) * config.frameRate / 1000);
      socket.frameRefilledAt = now;
      if (socket.frameTokens < 1) {
        socket.close(1008, 'Message rate limit reached.');
        return;
      }
      socket.frameTokens -= 1;
      let message;
      try { message = JSON.parse(data.toString('utf8')); } catch { return reject(socket, 'Invalid JSON frame.'); }
      if (!message || typeof message !== 'object' || Array.isArray(message)) return reject(socket, 'Invalid message.');
      if (message.type === 'join') return join(socket, req, message);
      if (message.type === 'leave') return leave(socket);
      if (message.type === 'ping') return send(socket, { type: 'pong' });
      const member = socket.member;
      if (!member) return reject(socket, 'Join a room first.');
      const room = rooms.get(member.roomId);
      if (message.type !== 'packet') return reject(socket, 'Unsupported message type.');
      if (room.mode === 'p2p') return reject(socket, 'P2P payloads must travel through the WebRTC data channel.');
      if (!message.packet || typeof message.packet !== 'object' || Array.isArray(message.packet)) return reject(socket, 'An encrypted packet object is required.');
      if (message.to !== undefined && !CLIENT_PATTERN.test(message.to)) return reject(socket, 'Invalid recipient identifier.');
      let delivered = false;
      for (const recipient of room.clients.values()) {
        if (recipient.clientId === member.clientId || (message.to && recipient.clientId !== message.to)) continue;
        send(recipient.socket, { type: 'packet', from: member.clientId, packet: message.packet });
        delivered = true;
      }
      if (message.to && !delivered) reject(socket, 'The recipient is no longer connected.');
    });
  });

  httpServer.on('upgrade', (req, socket, head) => {
    let pathname;
    try { pathname = new URL(req.url, 'http://local').pathname; } catch { return socket.destroy(); }
    const origin = req.headers.origin;
    if (origin) {
      try {
        if (new URL(origin).host !== req.headers.host) return socket.destroy();
      } catch { return socket.destroy(); }
    }
    const ip = requestIp(req);
    const sockets = [...wss.clients, ...(peerWss?.clients ?? [])];
    if (!takeRate(`upgrade:${ip}`, 60) || sockets.length >= config.maxClients * 2 + 16
      || sockets.filter((client) => client.ip === ip).length >= config.maxClientsPerIp * 2 + 2) {
      socket.write('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n');
      return socket.destroy();
    }
    if (pathname === '/signal') return wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
    if (pathname === '/peerjs/peerjs' && peerWss) return peerWss.handleUpgrade(req, socket, head, (ws) => {
      ws.ip = ip;
      ws.signalingTokens = 120;
      ws.signalingRefilledAt = Date.now();
      ws.on('message', (_data, binary) => {
        const now = Date.now();
        ws.signalingTokens = Math.min(120, ws.signalingTokens + (now - ws.signalingRefilledAt) * 60 / 1000);
        ws.signalingRefilledAt = now;
        if (binary || ws.signalingTokens < 1) { ws.close(1008, 'Peer signaling rate limit reached.'); return; }
        ws.signalingTokens -= 1;
      });
      peerWss.emit('connection', ws, req);
    });
    socket.destroy();
  });

  app.get('/health', (_req, res) => res.json({ status: 'ok', retention: 'none' }));

  app.get('/api/config', async (req, res) => {
    if (!takeRate(`config:${requestIp(req)}`, 120)) return res.status(429).json({ error: 'Configuration request rate limit reached.' });
    const iceServers = config.stunUrls.map((urls) => ({ urls }));
    if (config.turnPublicIp) {
      const host = isIP(config.turnPublicIp) === 6 ? `[${config.turnPublicIp}]` : config.turnPublicIp;
      iceServers.push({ urls: `stun:${host}:${config.turnPort}` });
      if (config.turnSecretFile) {
        try {
          const secret = (await readFile(config.turnSecretFile, 'utf8')).trim();
          if (secret.length < 32) throw new Error('Invalid TURN secret.');
          const expiresAt = Math.floor(Date.now() / 1000) + 6 * 60 * 60;
          const username = `${expiresAt}:${randomId()}`;
          const credential = createHmac('sha1', secret).update(username).digest('base64');
          iceServers.push({ urls: [`turn:${host}:${config.turnPort}?transport=udp`, `turn:${host}:${config.turnPort}?transport=tcp`], username, credential });
        } catch {
          return res.status(503).json({ error: 'TURN credentials are not configured correctly. Check the secret file on the server.' });
        }
      }
    }
    res.json({
      peer: { path: '/peerjs', key: 'peerjs' }, iceServers, maxFileBytes: MAX_FILE_BYTES,
      maxPacketBytes: MAX_FRAME_BYTES, retention: 'none',
      kdc: { enabled: Boolean(config.kdcKeysFile), strictThreeIps: config.strictThreeIps, serverIp: serverIp(req), sessionTtlMs: config.sessionTtlMs },
    });
  });

  app.post('/api/kdc/request', async (req, res) => {
    if (!config.kdcKeysFile) return res.status(503).json({ error: 'KDC master keys have not been configured on this server.' });
    const ip = requestIp(req);
    if (!takeRate(`kdc:${ip}`, 20)) return res.status(429).json({ error: 'KDC request rate limit reached. Try again in a minute.' });
    const { from, to, nonce, room: roomId } = req.body ?? {};
    if (!['Alice', 'Bob'].includes(from) || !['Alice', 'Bob'].includes(to) || from === to
      || !ROOM_PATTERN.test(roomId ?? '') || !NONCE_PATTERN.test(nonce ?? '')) {
      return res.status(400).json({ error: 'A valid sender, recipient, room hash, and hexadecimal request nonce are required.' });
    }
    const room = rooms.get(roomId);
    if (!room || room.keyMode !== 'kdc') return res.status(409).json({ error: 'Both KDC participants must first join the same room.' });
    const sender = [...room.clients.values()].find((member) => member.role === from);
    const recipient = [...room.clients.values()].find((member) => member.role === to);
    if (!sender || !recipient) return res.status(409).json({ error: 'Alice and Bob must both be connected before requesting a session key.' });
    if (sender.ip !== ip) return res.status(403).json({ error: 'The request IP address must match the registered sender.' });
    const kdcIp = serverIp(req);
    if (config.strictThreeIps && new Set([sender.ip, recipient.ip, kdcIp]).size !== 3) {
      return res.status(403).json({ error: 'The demonstration requires three different IP addresses for the KDC, Alice, and Bob.' });
    }
    const nonceId = `${roomId}:${from}:${nonce}`;
    if (nonceCache.has(nonceId)) return res.status(409).json({ error: 'This KDC request nonce has already been used.' });
    if (nonceCache.size >= 4096) return res.status(503).json({ error: 'The KDC replay cache is full. Try again after old requests expire.' });
    try {
      const keys = JSON.parse(await readFile(config.kdcKeysFile, 'utf8'));
      validateKey(keys[from]);
      validateKey(keys[to]);
      if (keys[from].length !== 32 || keys[to].length !== 32 || keys[from] === keys[to]) throw new Error('Each role needs a distinct 32-character ASCII master key.');
      // Reserve before encryption so concurrent copies of a request cannot both succeed.
      if (nonceCache.has(nonceId)) return res.status(409).json({ error: 'This KDC request nonce has already been used.' });
      const now = Date.now();
      nonceCache.set(nonceId, now + config.sessionTtlMs);
      const session = { sid: randomId(), from, to, room: roomId, sessionKey: randomAsciiKey(), issuedAt: now, expiresAt: now + config.sessionTtlMs };
      const ticket = seal(keys[to], encodeJson(session), `kdc-ticket:${roomId}`);
      const envelope = seal(keys[from], encodeJson({ ...session, nonce, ticket }), `kdc-response:${roomId}`);
      res.json({ envelope, serverIp: kdcIp, aliceIp: from === 'Alice' ? sender.ip : recipient.ip, bobIp: from === 'Bob' ? sender.ip : recipient.ip });
      // Session values are local to this request. No key, ticket, or chat history is retained.
    } catch {
      res.status(503).json({ error: 'KDC master keys could not be loaded. Each role needs a different 32-character printable ASCII key.' });
    }
  });

  if (config.peerEnabled) {
    const peer = peerTimerScope.run(true, () => config.peerServerFactory(httpServer, {
      path: '/', key: 'peerjs', allow_discovery: false, proxied: config.trustProxy,
      concurrent_limit: config.maxClients, alive_timeout: 30_000, expire_timeout: 1000,
      createWebSocketServer: () => {
        peerWss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024, perMessageDeflate: false });
        return peerWss;
      },
    }));
    peer.on('error', () => {});
    peerTimerScope.run(true, () => app.use('/peerjs', peer));
  }

  const publicDirectory = config.staticDir === ROOT ? path.join(ROOT, 'public') : config.staticDir;
  const vendorDirectory = path.join(ROOT, 'node_modules/peerjs');
  const staticOptions = { index: false, redirect: false, dotfiles: 'deny', etag: false, maxAge: 0 };

  app.use((req, res, next) => {
    if (!['GET', 'HEAD'].includes(req.method)) return next();
    const canonical = { '/index.html': '/' }[req.path];
    if (!canonical) return next();
    const queryIndex = req.originalUrl.indexOf('?');
    return res.redirect(308, canonical + (queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : ''));
  });
  function page(filename) {
    return (_req, res, next) => res.sendFile(filename, error => {
      if (!error) return;
      if (error.status === 404 || error.code === 'ENOENT') {
        if (!res.headersSent) res.status(404).json({ error: 'The requested resource was not found.' });
      } else next(error);
    });
  }
  app.get('/', page(path.join(config.staticDir, 'index.html')));
  app.get('/vendor/peerjs.min.js', page(path.join(vendorDirectory, 'dist/peerjs.min.js')));
  app.get('/vendor/peerjs-LICENSE.txt', page(path.join(vendorDirectory, 'LICENSE')));
  app.use('/vendor', express.static(path.join(ROOT, 'vendor'), staticOptions));
  app.use('/src', express.static(path.join(config.staticDir, 'src'), staticOptions));
  app.use(express.static(publicDirectory, staticOptions));
  app.use((_req, res) => res.status(404).json({ error: 'The requested resource was not found.' }));
  app.use((error, _req, res, _next) => {
    const status = error.type === 'entity.too.large' ? 413 : 400;
    res.status(status).json({ error: status === 413 ? 'The request body is too large.' : 'The request body must contain valid JSON.' });
  });

  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of rateBuckets) if (bucket.until <= now) rateBuckets.delete(key);
    for (const [key, expiresAt] of nonceCache) if (expiresAt <= now) nonceCache.delete(key);
    for (const socket of wss.clients) {
      if (!socket.alive) { socket.terminate(); continue; }
      socket.alive = false;
      socket.ping();
    }
  }, config.heartbeatMs);
  heartbeat.unref();

  return {
    app, httpServer, wss,
    address: () => httpServer.address(),
    stats: () => ({ rooms: rooms.size, clients: clients.size, replayEntries: nonceCache.size, storedMessages: 0 }),
    listen(port = 0, host = '127.0.0.1') {
      return new Promise((resolve, rejectListen) => {
        httpServer.once('error', rejectListen);
        httpServer.listen(port, host, () => { httpServer.off('error', rejectListen); resolve(httpServer.address()); });
      });
    },
    async close() {
      if (closing) return;
      closing = true;
      clearInterval(heartbeat);
      peerTimerHook.disable();
      peerTimerScope.disable();
      for (const timer of peerTimers.values()) clearTimeout(timer);
      peerTimers.clear();
      for (const socket of wss.clients) socket.terminate();
      for (const socket of peerWss?.clients ?? []) socket.terminate();
      wss.close();
      peerWss?.close();
      rooms.clear(); clients.clear(); nonceCache.clear(); rateBuckets.clear();
      if (httpServer.listening) await new Promise((resolve) => { httpServer.close(resolve); httpServer.closeAllConnections(); });
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = createAppServer();
  const port = integer(process.env.PORT, 3000, 1, 65535);
  await server.listen(port, process.env.HOST ?? '0.0.0.0');
  console.log(`Cipher Room is listening on port ${port}. No chat history is stored.`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await server.close(); process.exit(0); });
}
