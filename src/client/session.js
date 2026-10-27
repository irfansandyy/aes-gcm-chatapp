import { randomId, roomId, fingerprint, encodeJson, validateKey } from '../shared/crypto.js';
import { CryptoClient } from './crypto-client.js';
import { Transport } from './transport.js';
import { CHUNK_BYTES, MAX_FILE_BYTES, MAX_MESSAGES, HISTORY_BYTES, MAX_TEXT, WINDOW_CHUNKS,
  requireAscii, normalizeRoom, nonceResponse, toBase64, fromBase64, validateOffer, FileAssembler, ReplayWindow } from './protocol.js';

const exchangeLabels = [
  'Alice requests a session', 'KDC returns the session key and ticket',
  'Alice forwards Bob\'s ticket', 'Bob sends a fresh challenge', 'Alice answers the challenge'
];
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const safeId = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);

export function initialState() {
  return {
    status: 'idle', mode: 'relay', keyMode: 'shared', room: '', clientId: '', identity: '',
    participants: [], messages: [], selectedMessage: null, error: '', fingerprint: '', key: '', keyRevealed: false,
    exchange: [], transfer: null,
    stats: { sentBytes: 0, receivedBytes: 0, encryptedPackets: 0, rejectedPackets: 0 },
    connection: { localIp: '', serverIp: '', path: 'Not connected', secureContext: globalThis.isSecureContext ?? false, turnConfigured: false },
    config: null
  };
}

export class CipherSession {
  constructor(onChange, dependencies = {}) {
    this.onChange = onChange;
    this.makeCrypto = dependencies.makeCrypto || (() => new CryptoClient());
    this.makeTransport = dependencies.makeTransport || ((options, callbacks) => new Transport(options, callbacks));
    this.fetch = dependencies.fetch || globalThis.fetch.bind(globalThis);
    this.state = initialState();
    this.active = false;
    this.generation = 0;
    this.fileStore = new Map();
    this.authenticated = new Set();
    this.helloSent = new Set();
    this.syncRequested = new Set();
    this.replay = new Map();
    this.seenTickets = new Set();
    this.sequence = 0;
    this.sendQueue = Promise.resolve();
    this.receiveQueue = Promise.resolve();
    this.acknowledgements = new Map();
  }
  emit(patch = {}) {
    this.state = { ...this.state, ...patch };
    this.onChange(this.state);
  }
  notice(error) { this.emit({ error: error instanceof Error ? error.message : String(error) }); }
  updateStats(patch) { this.emit({ stats: { ...this.state.stats, ...patch } }); }
  async join(options) {
    this.leave();
    const generation = this.generation;
    try {
      const room = normalizeRoom(options.room);
      const identity = requireAscii(options.identity.trim(), 'Display name', 1, 32);
      if (!['relay', 'p2p'].includes(options.mode) || !['shared', 'kdc'].includes(options.keyMode)) throw new Error('Select a valid transport and key method.');
      if (options.keyMode === 'shared') requireAscii(options.secret, 'Encryption secret', 16, 256);
      else {
        if (!['Alice', 'Bob'].includes(options.role)) throw new Error('Choose Alice or Bob for the KDC demo.');
        validateKey(options.masterKey);
      }
      this.active = true;
      this.options = { ...options, room, identity, secret: undefined, masterKey: undefined };
      this.masterKey = options.masterKey || '';
      this.clientId = randomId();
      this.directoryRoom = roomId(room, options.mode, options.keyMode);
      this.crypto = this.makeCrypto();
      this.emit({ ...initialState(), status: options.keyMode === 'shared' ? 'deriving' : 'connecting',
        room, identity, mode: options.mode, keyMode: options.keyMode, clientId: this.clientId,
        exchange: options.keyMode === 'kdc' ? exchangeLabels.map((label, index) => ({ step: index + 1, label, detail: 'Waiting', state: 'pending' })) : [] });
      const response = await this.fetch('/api/config', { cache: 'no-store' });
      if (!response.ok) throw new Error('The server configuration is unavailable.');
      const config = await response.json();
      if (!this.isCurrent(generation)) return;
      if (options.keyMode === 'kdc' && !config.kdc?.enabled) throw new Error('The KDC is not configured. Run the configuration script on the server first.');
      if (options.forceRelay && !(config.iceServers || []).some(item => (Array.isArray(item.urls) ? item.urls : [item.urls]).some(url => /^turns?:/.test(url)))) {
        throw new Error('TURN is not configured on this server. Disable Force TURN or configure the self-hosted TURN service.');
      }
      this.emit({ config, connection: { ...this.state.connection, serverIp: config.kdc?.serverIp || '',
        turnConfigured: (config.iceServers || []).some(item => JSON.stringify(item.urls).includes('turn:')) } });
      if (options.keyMode === 'shared') {
        const key = await this.crypto.call('derive', options.secret, room, options.mode);
        if (!this.isCurrent(generation)) return;
        await this.setKey(key);
      }
      if (!this.isCurrent(generation)) return;
      this.emit({ status: 'connecting' });
      this.transport = this.makeTransport({ ...this.options, config, roomId: this.directoryRoom,
        clientId: this.clientId, resumeToken: randomId(), peerId: `cr-${this.clientId}` }, {
        onPresence: message => { if (this.isCurrent(generation)) this.onPresence(message); },
        onPeerOpen: id => { if (this.isCurrent(generation)) this.onPeerOpen(id).catch(error => { if (this.isCurrent(generation)) this.notice(error); }); },
        onPeerClose: id => { if (this.isCurrent(generation)) this.onPeerClose(id); },
        onPacket: (packet, from) => {
          if (!this.isCurrent(generation)) return;
          this.receiveQueue = this.receiveQueue.then(() => this.receive(packet, from)).catch(error => {
            if (this.isCurrent(generation)) {
              this.updateStats({ rejectedPackets: this.state.stats.rejectedPackets + 1 });
              this.notice(`Packet rejected: ${error.message}`);
            }
          });
        },
        onNotice: error => { if (this.isCurrent(generation)) this.notice(error); },
        onSignalLost: () => {
          if (!this.isCurrent(generation)) return;
          if (this.state.mode === 'relay') {
            this.authenticated.clear();
            this.helloSent.clear();
            this.syncRequested.clear();
          }
          this.emit({ status: this.state.mode === 'p2p' && this.authenticated.size ? 'ready' : 'reconnecting' });
        },
        onPath: path => { if (this.isCurrent(generation)) this.emit({ connection: { ...this.state.connection, path } }); }
      });
      await this.transport.start();
    } catch (error) {
      if (this.generation !== generation) return;
      this.transport?.close();
      this.crypto?.close();
      this.active = false;
      this.emit({ status: 'error', error: error.message });
    }
  }
  isCurrent(generation) { return this.active && this.generation === generation; }
  async setKey(key) {
    const generation = this.generation;
    await this.crypto.call('setKey', key);
    if (!this.isCurrent(generation)) throw new Error('Session closed.');
    this.authenticated.clear();
    this.helloSent.clear();
    this.syncRequested.clear();
    this.replay.clear();
    this.proofSent = false;
    this.proofVerified = false;
    this.emit({ key, fingerprint: fingerprint(key), keyRevealed: false });
  }
  onPresence(message) {
    if (message.type === 'joined') this.emit({ error: '' });
    const participants = message.participants || [];
    const me = participants.find(item => item.clientId === this.clientId);
    this.emit({ participants, connection: { ...this.state.connection,
      localIp: me?.ip || message.ip || this.state.connection.localIp,
      serverIp: message.serverIp || this.state.connection.serverIp,
      path: this.state.mode === 'relay' ? 'Encrypted room relay' : this.state.connection.path } });
    const peers = participants.filter(item => item.clientId !== this.clientId);
    if (!peers.length && !this.authenticated.size) this.emit({ status: 'waiting' });
    else if (!this.authenticated.size) this.emit({ status: 'authenticating' });
    if (this.state.mode === 'relay') {
      const ids = new Set(peers.map(item => item.clientId));
      for (const id of this.authenticated) if (!ids.has(id)) this.onPeerClose(id);
    }
  }
  async onPeerOpen(id) {
    if (this.state.keyMode === 'kdc') {
      if (this.options.role === 'Alice' && (!this.state.key || this.kdcRemote !== id || !this.proofSent) && !this.handshakeStarted) {
        await this.startKdc(id);
        return;
      }
      if (!this.state.key) return;
    }
    if (this.state.key) await this.sendHello(id);
  }
  onPeerClose(id) {
    this.authenticated.delete(id);
    this.helloSent.delete(id);
    this.syncRequested.delete(id);
    if (this.state.keyMode === 'kdc' && this.kdcRemote === id) this.handshakeStarted = false;
    if (!this.authenticated.size && this.active) this.emit({ status: 'waiting' });
    if (this.sending?.to === id || this.receiving?.from === id) this.cancelTransfer('The connection was interrupted. Request the file again after reconnecting.');
  }
  async sendHello(to) {
    if (this.helloSent.has(to)) return;
    this.helloSent.add(to);
    try { await this.sendEncrypted({ kind: 'hello', identity: this.state.identity, version: 1 }, to); }
    catch (error) { this.helloSent.delete(to); throw error; }
  }
  step(number, detail, envelope) {
    this.emit({ exchange: this.state.exchange.map(item => item.step === number ? {
      ...item, state: 'complete', detail, time: Date.now(), ...(envelope ? { envelope } : {})
    } : item) });
  }
  async startKdc(to) {
    const generation = this.generation;
    const remote = this.state.participants.find(item => item.clientId === to);
    if (remote?.role !== 'Bob') return;
    this.handshakeStarted = true;
    this.proofSent = false;
    this.proofVerified = false;
    this.emit({ status: 'authenticating', exchange: exchangeLabels.map((label, index) => ({ step: index + 1, label, detail: 'Waiting', state: 'pending' })) });
    this.kdcRemote = to;
    this.requestNonce = randomId();
    this.step(1, `Alice, Bob and nonce N1 ${this.requestNonce} submitted to the KDC.`);
    try {
      const response = await this.fetch('/api/kdc/request', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: 'Alice', to: 'Bob', nonce: this.requestNonce, room: this.directoryRoom }) });
      const body = await response.json();
      if (!this.isCurrent(generation)) return;
      if (!response.ok) throw new Error(body.error || 'The KDC rejected this request.');
      const result = await this.crypto.call('openWithKey', this.masterKey, body.envelope, `kdc-response:${this.directoryRoom}`);
      if (!this.isCurrent(generation)) return;
      this.checkKdcPayload(result, 'Alice', 'Bob');
      if (result.nonce !== this.requestNonce) throw new Error('The KDC response did not echo Alice\'s nonce.');
      this.sid = result.sid;
      this.expiresAt = result.expiresAt;
      await this.setKey(result.sessionKey);
      this.armExpiry();
      this.step(2, 'Alice verified N1 and decrypted the ASCII session key. Bob\'s ticket remains encrypted with Bob\'s master key.', body.envelope);
      await this.transport.send({ type: 'kdc-ticket', ticket: result.ticket }, to);
      this.step(3, 'Bob\'s encrypted ticket sent to Bob.', result.ticket);
    } catch (error) {
      if (!this.isCurrent(generation)) return;
      this.handshakeStarted = false;
      this.emit({ exchange: this.state.exchange.map(item => item.state === 'pending' ? { ...item, state: 'failed' } : item) });
      throw error;
    }
  }
  checkKdcPayload(payload, from, to) {
    if (!payload || payload.from !== from || payload.to !== to || payload.room !== this.directoryRoom ||
        !safeId(payload.sid) || !Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt) ||
        payload.issuedAt > Date.now() + 30000 || payload.expiresAt <= Date.now() ||
        payload.expiresAt - payload.issuedAt > 15 * 60 * 1000) throw new Error('Invalid, expired or misdirected KDC ticket.');
    validateKey(payload.sessionKey);
  }
  armExpiry() {
    clearTimeout(this.expiryTimer);
    this.expiryTimer = setTimeout(() => {
      if (!this.active) return;
      this.authenticated.clear();
      this.emit({ status: 'waiting', error: 'The 15-minute KDC session expired. Leave and join again to distribute a new key.' });
    }, Math.max(0, this.expiresAt - Date.now()));
  }
  async receiveKdc(packet, from) {
    const generation = this.generation;
    if (this.state.keyMode !== 'kdc') throw new Error('KDC packets are not accepted in a shared-secret room.');
    const participant = this.state.participants.find(item => item.clientId === from);
    if (packet.type === 'kdc-ticket') {
      if (this.options.role !== 'Bob' || participant?.role !== 'Alice') throw new Error('The KDC ticket has an unexpected recipient.');
      const ticket = await this.crypto.call('openWithKey', this.masterKey, packet.ticket, `kdc-ticket:${this.directoryRoom}`);
      if (!this.isCurrent(generation)) return;
      this.checkKdcPayload(ticket, 'Alice', 'Bob');
      if (this.seenTickets.has(ticket.sid)) throw new Error('A repeated KDC ticket was rejected.');
      if (this.seenTickets.size > 512) throw new Error('KDC ticket limit reached. Leave and join a new session.');
      this.seenTickets.add(ticket.sid);
      this.sid = ticket.sid;
      this.kdcRemote = from;
      this.expiresAt = ticket.expiresAt;
      await this.setKey(ticket.sessionKey);
      this.armExpiry();
      this.step(1, 'Alice requested a session. Bob observes this step through the valid ticket.');
      this.step(2, 'The KDC issued a ticket encrypted with Bob\'s master key.');
      this.step(3, 'Bob decrypted and validated the ticket.', packet.ticket);
      this.challenge = randomId();
      const envelope = await this.crypto.call('seal', { nonce: this.challenge, sid: this.sid }, `kdc-step4:${this.directoryRoom}:${this.sid}`);
      await this.transport.send({ type: 'kdc-challenge', sid: this.sid, envelope }, from);
      this.step(4, `Bob generated N2 ${this.challenge} and sent it encrypted with the session key.`, envelope);
    } else if (packet.type === 'kdc-challenge') {
      if (this.options.role !== 'Alice' || from !== this.kdcRemote || packet.sid !== this.sid || this.proofSent) throw new Error('Unexpected KDC challenge.');
      const challenge = await this.crypto.call('open', packet.envelope, `kdc-step4:${this.directoryRoom}:${this.sid}`);
      if (!this.isCurrent(generation)) return;
      if (challenge.sid !== this.sid) throw new Error('KDC challenge session mismatch.');
      const response = nonceResponse(challenge.nonce);
      this.step(4, `Alice decrypted Bob\'s fresh nonce N2 ${challenge.nonce}.`, packet.envelope);
      const envelope = await this.crypto.call('seal', { response, sid: this.sid }, `kdc-step5:${this.directoryRoom}:${this.sid}`);
      await this.transport.send({ type: 'kdc-proof', sid: this.sid, envelope }, from);
      this.proofSent = true;
      this.step(5, 'Alice returned f(N2) = N2 - 1. Waiting for Bob\'s authenticated acknowledgement.', envelope);
    } else if (packet.type === 'kdc-proof') {
      if (this.options.role !== 'Bob' || from !== this.kdcRemote || packet.sid !== this.sid || !this.challenge) throw new Error('Unexpected KDC proof.');
      const proof = await this.crypto.call('open', packet.envelope, `kdc-step5:${this.directoryRoom}:${this.sid}`);
      if (!this.isCurrent(generation)) return;
      if (proof.sid !== this.sid || proof.response !== nonceResponse(this.challenge)) throw new Error('Alice\'s challenge response did not match f(N2).');
      this.challenge = '';
      this.proofVerified = true;
      this.step(5, 'Bob verified f(N2) = N2 - 1. The five-step exchange is complete.', packet.envelope);
      await this.sendHello(from);
    }
  }
  sendEncrypted(inner, to, allowOffline = false) {
    const generation = this.generation;
    const task = this.sendQueue.then(async () => {
      if (!this.isCurrent(generation) || !this.state.key) throw new Error('An encryption key has not been established.');
      if (this.state.keyMode === 'kdc' && this.expiresAt <= Date.now()) throw new Error('The KDC session key expired.');
      const header = { v: 1, room: this.directoryRoom, epoch: this.state.fingerprint, sender: this.clientId, id: randomId(), seq: this.sequence++ };
      const aad = JSON.stringify(header);
      const start = performance.now();
      const envelope = await this.crypto.call('seal', inner, aad);
      if (!this.isCurrent(generation)) throw new Error('Session closed.');
      const localOnly = allowOffline && !this.authenticated.size;
      if (!localOnly) await this.transport.send({ type: 'encrypted', header, envelope }, to);
      if (!this.isCurrent(generation)) throw new Error('Session closed.');
      const details = { ...envelope, aad, plaintextBytes: encodeJson(inner).length,
        ciphertextBytes: envelope.ciphertext.length / 2, elapsedMs: performance.now() - start,
        keyFingerprint: this.state.fingerprint, packetId: header.id, localOnly };
      this.updateStats({ sentBytes: this.state.stats.sentBytes + (localOnly ? 0 : details.ciphertextBytes),
        encryptedPackets: this.state.stats.encryptedPackets + 1 });
      return details;
    });
    this.sendQueue = task.catch(() => {});
    return task;
  }
  async receive(packet, from) {
    const generation = this.generation;
    if (!this.active || !packet || !safeId(from)) return;
    if (packet.type?.startsWith('kdc-')) return this.receiveKdc(packet, from);
    if (packet.type !== 'encrypted' || !this.state.key) throw new Error('No shared encryption key is available.');
    const { header, envelope } = packet;
    if (!header || header.v !== 1 || header.sender !== from || header.room !== this.directoryRoom ||
        header.epoch !== this.state.fingerprint || !safeId(header.id) || !Number.isSafeInteger(header.seq) || header.seq < 0) {
      throw new Error('The packet belongs to another sender, room or key. Check the room and encryption secret.');
    }
    if (this.state.keyMode === 'kdc' && this.expiresAt <= Date.now()) throw new Error('Expired KDC session.');
    const aad = JSON.stringify(header);
    const start = performance.now();
    const inner = await this.crypto.call('open', envelope, aad);
    if (!this.isCurrent(generation)) return;
    if (!inner || typeof inner !== 'object' || typeof inner.kind !== 'string') throw new Error('Malformed encrypted content.');
    if (!this.replay.has(from)) this.replay.set(from, new ReplayWindow());
    if (!this.replay.get(from).accept(header.seq)) throw new Error('Repeated or stale encrypted packet.');
    const details = { ...envelope, aad, plaintextBytes: encodeJson(inner).length,
      ciphertextBytes: envelope.ciphertext.length / 2, elapsedMs: performance.now() - start,
      keyFingerprint: this.state.fingerprint, packetId: header.id };
    this.updateStats({ receivedBytes: this.state.stats.receivedBytes + details.ciphertextBytes });
    if (inner.kind === 'hello') {
      if (this.state.keyMode === 'kdc' && !(this.options.role === 'Bob' ? this.proofVerified : this.proofSent)) throw new Error('Chat cannot start before step five completes.');
      requireAscii(inner.identity, 'Display name', 1, 32);
      if (inner.version !== 1) throw new Error('Unsupported peer protocol.');
      this.authenticated.add(from);
      if (this.state.keyMode === 'kdc' && this.options.role === 'Alice') {
        this.step(5, 'Alice returned f(N2) = N2 - 1 and received Bob\'s authenticated acknowledgement. The exchange is complete.');
      }
      this.emit({ status: 'ready', error: '' });
      await this.sendHello(from);
      if (!this.syncRequested.has(from)) {
        this.syncRequested.add(from);
        await this.sendEncrypted({ kind: 'sync-request' }, from);
      }
      return;
    }
    if (!this.authenticated.has(from)) throw new Error('The sender has not confirmed the encryption key.');
    if (inner.kind === 'text') {
      requireAscii(inner.text, 'Message', 1, MAX_TEXT, false);
      if (!safeId(inner.id) || !Number.isFinite(inner.time)) throw new Error('Invalid message identifier.');
      requireAscii(inner.senderName, 'Sender name', 1, 32);
      this.addMessage({ id: inner.id, kind: 'text', text: inner.text, senderId: from,
        senderName: inner.senderName, time: inner.time, outgoing: false, crypto: details });
    } else if (inner.kind === 'sync-request') {
      const snapshot = [...this.state.messages];
      this.syncHistory(snapshot, from).catch(error => { if (this.isCurrent(generation)) this.notice(error); });
    } else if (inner.kind === 'sync-item') {
      const message = inner.message;
      if (!message || !safeId(message.id) || !safeId(message.senderId) || !Number.isFinite(message.time)) throw new Error('Invalid history record.');
      requireAscii(message.senderName, 'Sender name', 1, 32);
      if (message.kind === 'text') requireAscii(message.text, 'Message', 1, MAX_TEXT, false);
      else if (message.kind === 'file') {
        message.file = { ...validateOffer(message.file), progress: 0, status: 'offered', available: this.fileStore.has(message.file.id) };
        if (inner.available) this.rememberHolder(message.file.id, from);
      } else throw new Error('Unknown history record.');
      this.addMessage({ ...message, queued: false, outgoing: message.senderId === this.clientId, recovered: true });
    } else if (inner.kind === 'file-offer') {
      const file = validateOffer(inner.file);
      if (!safeId(inner.id) || inner.id !== file.id || !Number.isFinite(inner.time)) throw new Error('Invalid file message.');
      requireAscii(inner.senderName, 'Sender name', 1, 32);
      this.rememberHolder(file.id, from);
      this.addMessage({ id: inner.id, kind: 'file', senderId: from, senderName: inner.senderName,
        time: inner.time, outgoing: false, file: { ...file, status: 'offered', progress: 0, available: false }, crypto: details });
    } else if (inner.kind === 'file-request') {
      this.startSending(inner.fileId, from).catch(error => this.notice(error));
    } else if (inner.kind === 'file-start') {
      if (!this.receiving || this.receiving.file.id !== inner.fileId || this.receiving.from !== from || inner.chunkBytes !== CHUNK_BYTES) throw new Error('Unexpected file transfer.');
      this.receiving.started = true;
    } else if (inner.kind === 'file-chunk') {
      const receive = this.receiving;
      if (!receive || !receive.started || receive.from !== from || receive.file.id !== inner.fileId) throw new Error('Unexpected file chunk.');
      receive.assembler.append(inner.index, fromBase64(inner.data));
      receive.lastProgress = Date.now();
      const progress = receive.file.size ? receive.assembler.bytes / receive.file.size * 100 : 100;
      if (inner.index % WINDOW_CHUNKS === WINDOW_CHUNKS - 1 || receive.assembler.bytes === receive.file.size) {
        this.fileProgress(inner.fileId, progress, 'receiving', details);
      }
      await this.sendEncrypted({ kind: 'file-ack', fileId: inner.fileId, index: inner.index }, from);
    } else if (inner.kind === 'file-ack' || inner.kind === 'file-receipt') {
      const acknowledgement = this.acknowledgements.get(`${from}:${inner.fileId}:${inner.kind === 'file-receipt' ? 'end' : inner.index}`);
      if (acknowledgement) { clearTimeout(acknowledgement.timer); acknowledgement.resolve(); this.acknowledgements.delete(acknowledgement.key); }
    } else if (inner.kind === 'file-end') {
      const receive = this.receiving;
      if (!receive || receive.from !== from || receive.file.id !== inner.fileId) throw new Error('Unexpected file completion.');
      const blob = receive.assembler.finish(inner.size, inner.chunks);
      this.fileStore.set(inner.fileId, blob);
      this.rememberHolder(inner.fileId, this.clientId);
      this.fileProgress(inner.fileId, 100, 'complete', undefined, true);
      this.receiving = null;
      this.stopReceiveWatchdog();
      this.emit({ transfer: null });
      await this.sendEncrypted({ kind: 'file-receipt', fileId: inner.fileId }, from);
    } else if (inner.kind === 'file-cancel') {
      if (this.sending?.fileId === inner.fileId && this.sending.to === from || this.receiving?.file.id === inner.fileId && this.receiving.from === from) {
        this.cancelTransfer('The other participant cancelled the transfer.', false);
      }
    } else throw new Error('Unknown encrypted content type.');
  }
  async syncHistory(messages, to) {
    const generation = this.generation;
    for (const message of messages) {
      if (!this.isCurrent(generation) || !this.authenticated.has(to)) return;
      const safe = { ...message, crypto: message.crypto ? { ...message.crypto, ciphertext: message.crypto.ciphertext.slice(0, 512), truncated: message.crypto.ciphertext.length > 512 } : undefined };
      await this.sendEncrypted({ kind: 'sync-item', message: safe, available: message.file ? this.fileStore.has(message.file.id) : false }, to);
    }
  }
  addMessage(message) {
    if (this.state.messages.some(item => item.id === message.id)) return;
    let messages = [...this.state.messages, message].sort((a, b) => a.time - b.time || a.id.localeCompare(b.id));
    let bytes = messages.reduce((total, item) => total + (item.text?.length || 0) + (item.crypto?.ciphertext?.length || 0) + 512, 0);
    while (messages.length > MAX_MESSAGES || bytes > HISTORY_BYTES) {
      const removed = messages.shift();
      bytes -= (removed.text?.length || 0) + (removed.crypto?.ciphertext?.length || 0) + 512;
      if (removed.file && removed.file.id !== this.sending?.fileId && removed.file.id !== this.receiving?.file.id) this.fileStore.delete(removed.file.id);
    }
    this.emit({ messages });
  }
  async sendText(text) {
    const generation = this.generation;
    try {
      requireAscii(text, 'Message', 1, MAX_TEXT, false);
      if (!text.trim()) return;
      if (!this.active || !this.state.key) throw new Error('Join a room before sending a message.');
      if (this.state.keyMode === 'kdc' && !(this.options.role === 'Bob' ? this.proofVerified : this.proofSent)) throw new Error('Wait for the five KDC steps to complete.');
      const message = { id: randomId(), kind: 'text', text, senderId: this.clientId, senderName: this.state.identity, time: Date.now(), outgoing: true };
      message.crypto = await this.sendEncrypted({ kind: 'text', id: message.id, text, senderName: message.senderName, time: message.time }, undefined, true);
      if (!this.isCurrent(generation)) return;
      if (message.crypto.localOnly) message.queued = true;
      this.addMessage(message);
    } catch (error) { if (this.isCurrent(generation)) { this.notice(error); throw error; } }
  }
  async sendFile(file) {
    const generation = this.generation;
    try {
      if (!this.active || !this.state.key) throw new Error('Join a room before offering a file.');
      if (this.state.keyMode === 'kdc' && !(this.options.role === 'Bob' ? this.proofVerified : this.proofSent)) throw new Error('Wait for the five KDC steps to complete.');
      const metadata = validateOffer({ id: randomId(), name: file.name, mime: file.type || 'application/octet-stream', size: file.size });
      this.fileStore.set(metadata.id, file);
      const message = { id: metadata.id, kind: 'file', senderId: this.clientId, senderName: this.state.identity, time: Date.now(), outgoing: true,
        file: { ...metadata, status: 'complete', progress: 100, available: true } };
      message.crypto = await this.sendEncrypted({ kind: 'file-offer', id: message.id, file: metadata, senderName: message.senderName, time: message.time }, undefined, true);
      if (!this.isCurrent(generation)) return;
      this.addMessage(message);
    } catch (error) { if (this.isCurrent(generation)) { this.notice(error); throw error; } }
  }
  rememberHolder(fileId, peerId) {
    this.holders ||= new Map();
    if (!this.holders.has(fileId)) this.holders.set(fileId, new Set());
    this.holders.get(fileId).add(peerId);
  }
  fileProgress(id, progress, status, crypto, available = false) {
    const messages = this.state.messages.map(message => message.file?.id === id ? {
      ...message, file: { ...message.file, progress, status, available: available || message.file.available },
      ...(crypto ? { crypto: { ...crypto, ciphertext: crypto.ciphertext.slice(0, 1024), truncated: crypto.ciphertext.length > 1024 } } : {})
    } : message);
    this.emit({ messages, selectedMessage: this.state.selectedMessage?.file?.id === id ? messages.find(item => item.id === id) : this.state.selectedMessage,
      transfer: ['sending', 'receiving'].includes(status) ? { id, name: messages.find(item => item.id === id)?.file.name, progress,
        size: messages.find(item => item.id === id)?.file.size, direction: status === 'sending' ? 'send' : 'receive', status } : this.state.transfer });
  }
  async downloadFile(messageId) {
    const generation = this.generation;
    try {
      const message = this.state.messages.find(item => item.id === messageId);
      if (!message?.file) throw new Error('File offer not found.');
      const file = this.fileStore.get(message.file.id);
      if (file) {
        const url = URL.createObjectURL(file);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = message.file.name;
        anchor.rel = 'noopener';
        anchor.click();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        return;
      }
      if (this.sending || this.receiving) throw new Error('Finish or cancel the current file transfer first.');
      const from = [...(this.holders?.get(message.file.id) || []), message.senderId].find(id => this.authenticated.has(id));
      if (!from) throw new Error('No connected participant has this file. It was not stored on the server.');
      const heldBytes = [...this.fileStore.values()].filter(item => !(item instanceof File)).reduce((sum, item) => sum + item.size, 0);
      if (heldBytes + message.file.size > MAX_FILE_BYTES) throw new Error('The 1 GiB received-file memory budget would be exceeded. Forget history or join a fresh session.');
      this.receiving = { file: message.file, from, assembler: new FileAssembler(message.file), lastProgress: Date.now() };
      this.fileProgress(message.file.id, 0, 'receiving');
      this.startReceiveWatchdog();
      await this.sendEncrypted({ kind: 'file-request', fileId: message.file.id }, from);
    } catch (error) { if (this.isCurrent(generation)) this.notice(error); }
  }
  waitForAck(to, fileId, index) {
    const key = `${to}:${fileId}:${index}`;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.acknowledgements.delete(key); reject(new Error('The file transfer timed out. Request it again after reconnecting.')); }, 45000);
      this.acknowledgements.set(key, { key, resolve, reject, timer });
    });
    promise.catch(() => {});
    return promise;
  }
  async startSending(fileId, to) {
    const generation = this.generation;
    if (!safeId(fileId)) throw new Error('Invalid file request.');
    const file = this.fileStore.get(fileId);
    if (!file) { await this.sendEncrypted({ kind: 'file-cancel', fileId }, to); throw new Error('This file is no longer available in memory.'); }
    if (this.sending || this.receiving) { await this.sendEncrypted({ kind: 'file-cancel', fileId }, to); return; }
    const sending = { fileId, to, cancelled: false };
    this.sending = sending;
    this.fileProgress(fileId, 0, 'sending');
    try {
      await this.sendEncrypted({ kind: 'file-start', fileId, chunkBytes: CHUNK_BYTES }, to);
      let window = [];
      const count = Math.ceil(file.size / CHUNK_BYTES);
      for (let index = 0; index < count; index++) {
        if (sending.cancelled || this.sending !== sending) throw new Error('File transfer cancelled.');
        const bytes = new Uint8Array(await file.slice(index * CHUNK_BYTES, (index + 1) * CHUNK_BYTES).arrayBuffer());
        if (!this.isCurrent(generation) || sending.cancelled || this.sending !== sending) throw new Error('File transfer stopped.');
        const acknowledgement = this.waitForAck(to, fileId, index);
        const details = await this.sendEncrypted({ kind: 'file-chunk', fileId, index, data: toBase64(bytes) }, to);
        window.push(acknowledgement);
        if (window.length >= WINDOW_CHUNKS || index === count - 1) {
          await Promise.all(window);
          if (!this.isCurrent(generation) || sending.cancelled) throw new Error('File transfer stopped.');
          window = [];
          this.fileProgress(fileId, (index + 1) / count * 100, 'sending', details);
          await pause(0);
        }
      }
      if (!this.isCurrent(generation) || sending.cancelled) throw new Error('File transfer stopped.');
      const finalReceipt = this.waitForAck(to, fileId, 'end');
      await this.sendEncrypted({ kind: 'file-end', fileId, size: file.size, chunks: count }, to);
      await finalReceipt;
      if (!this.isCurrent(generation) || sending.cancelled) throw new Error('File transfer stopped.');
      this.fileProgress(fileId, 100, 'complete', undefined, true);
    } catch (error) {
      if (!this.isCurrent(generation)) return;
      this.fileProgress(fileId, 0, sending.cancelled ? 'cancelled' : 'interrupted');
      if (!sending.cancelled) this.notice(error);
    } finally {
      if (this.isCurrent(generation)) {
        if (this.sending === sending) this.sending = null;
        if (!this.receiving) this.emit({ transfer: null });
        this.clearAcks(fileId);
      }
    }
  }
  clearAcks(fileId) {
    for (const [key, ack] of this.acknowledgements) {
      if (!fileId || key.includes(`:${fileId}:`)) { clearTimeout(ack.timer); ack.reject(new Error('File transfer stopped.')); this.acknowledgements.delete(key); }
    }
  }
  startReceiveWatchdog() {
    this.stopReceiveWatchdog();
    this.receiveWatchdog = setInterval(() => {
      if (this.receiving && Date.now() - this.receiving.lastProgress > 60000) this.cancelTransfer('The incoming transfer timed out. Request the file again.');
    }, 10000);
  }
  stopReceiveWatchdog() { clearInterval(this.receiveWatchdog); }
  cancelTransfer(reason = '', notify = true) {
    const fileId = this.sending?.fileId || this.receiving?.file.id;
    const to = this.sending?.to || this.receiving?.from;
    if (this.sending) this.sending.cancelled = true;
    if (fileId && notify && this.active) this.sendEncrypted({ kind: 'file-cancel', fileId }, to).catch(() => {});
    this.clearAcks(fileId);
    this.receiving = null;
    this.stopReceiveWatchdog();
    if (fileId) this.fileProgress(fileId, 0, reason ? 'interrupted' : 'cancelled');
    this.emit({ transfer: null, ...(reason ? { error: reason } : {}) });
  }
  forgetHistory() {
    this.cancelTransfer();
    this.fileStore.clear();
    this.holders?.clear();
    this.emit({ messages: [], selectedMessage: null });
  }
  leave() {
    this.active = false;
    this.generation++;
    this.transport?.close();
    this.transport = null;
    this.crypto?.close();
    this.crypto = null;
    clearTimeout(this.expiryTimer);
    this.cancelTransfer('', false);
    this.sending = null;
    this.fileStore.clear();
    this.holders?.clear();
    this.authenticated.clear();
    this.helloSent.clear();
    this.syncRequested.clear();
    this.replay.clear();
    this.seenTickets.clear();
    this.handshakeStarted = false;
    this.proofSent = false;
    this.proofVerified = false;
    this.sequence = 0;
    this.sid = '';
    this.kdcRemote = '';
    this.challenge = '';
    this.masterKey = '';
    this.options = null;
    this.expiresAt = 0;
    this.sendQueue = Promise.resolve();
    this.receiveQueue = Promise.resolve();
    this.emit(initialState());
  }
}
