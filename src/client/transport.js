const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

export class Transport {
  constructor(options, callbacks) {
    Object.assign(this, options);
    this.callbacks = callbacks;
    this.connections = new Map();
    this.participants = [];
    this.stopped = false;
    this.retryCount = 0;
    this.timers = new Set();
  }
  later(action, milliseconds) {
    const timer = setTimeout(() => { this.timers.delete(timer); if (!this.stopped) action(); }, milliseconds);
    this.timers.add(timer);
  }
  async start() {
    if (this.mode === 'p2p') {
      if (!globalThis.RTCPeerConnection) throw new Error('WebRTC data channels are unavailable in this browser. Use room relay or another browser with WebRTC support.');
      const Peer = globalThis.Peer;
      if (typeof Peer !== 'function') throw new Error('The local PeerJS script did not load. Refresh this page and try again.');
      this.peer = new Peer(this.peerId, {
        host: location.hostname,
        port: Number(location.port || 80),
        path: this.config.peer?.path || '/peerjs',
        secure: false,
        debug: 0,
        config: { iceServers: this.config.iceServers || [], iceTransportPolicy: this.forceRelay ? 'relay' : 'all' }
      });
      this.peer.on('connection', connection => this.bindConnection(connection));
      this.peer.on('disconnected', () => this.later(() => { if (!this.peer.destroyed) this.peer.reconnect(); }, 1500));
      this.peer.on('error', error => {
        if (error.type === 'peer-unavailable') return;
        this.callbacks.onNotice(error.type === 'network' ? 'Peer signaling is reconnecting.' : `Peer connection: ${error.message}`);
      });
      await new Promise((resolve, reject) => {
        this.peer.once('open', resolve);
        this.peer.once('error', reject);
        this.later(() => reject(new Error('Peer signaling did not connect within 20 seconds.')), 20000);
      });
    }
    this.openDirectory();
  }
  openDirectory() {
    if (this.stopped || this.ws?.readyState === WebSocket.OPEN || this.ws?.readyState === WebSocket.CONNECTING) return;
    const ws = new WebSocket(`ws://${location.host}/signal`);
    let joined = false;
    this.ws = ws;
    ws.onopen = () => ws.send(JSON.stringify({ type: 'join', room: this.roomId, mode: this.mode,
      clientId: this.clientId, resumeToken: this.resumeToken, peerId: this.peerId, identity: this.identity,
      role: this.keyMode === 'kdc' ? this.role : null, keyMode: this.keyMode }));
    ws.onmessage = ({ data }) => {
      if (typeof data !== 'string' || data.length > 85000) return;
      try {
        const message = JSON.parse(data);
        if (message.type === 'error') {
          this.callbacks.onNotice(message.error || message.message || 'Connection rejected.');
          if (!joined) ws.close();
          return;
        }
        if (message.type === 'joined' || message.type === 'presence') {
          if (message.type === 'joined') joined = true;
          this.retryCount = 0;
          this.participants = message.participants || [];
          this.callbacks.onPresence(message);
          this.connectPeers();
          if (this.mode === 'relay') {
            for (const participant of this.participants) {
              if (participant.clientId !== this.clientId) this.callbacks.onPeerOpen(participant.clientId);
            }
          }
        } else if (message.type === 'packet' && this.mode === 'relay') {
          this.callbacks.onPacket(message.packet, message.from);
        }
      } catch { this.callbacks.onNotice('A malformed signaling frame was rejected.'); }
    };
    ws.onclose = () => {
      if (this.stopped) return;
      this.callbacks.onSignalLost();
      this.later(() => this.openDirectory(), Math.min(10000, 500 * 2 ** Math.min(this.retryCount++, 5)));
    };
    ws.onerror = () => {};
  }
  connectPeers() {
    if (this.mode !== 'p2p' || !this.peer?.open) return;
    for (const participant of this.participants) {
      if (participant.clientId === this.clientId || participant.clientId < this.clientId ||
          this.connections.has(participant.clientId)) continue;
      const connection = this.peer.connect(participant.peerId, {
        reliable: true, serialization: 'raw', metadata: { clientId: this.clientId }
      });
      this.bindConnection(connection, participant.clientId);
    }
  }
  bindConnection(connection, knownId) {
    let remoteId = knownId;
    connection.on('open', () => {
      const participant = this.participants.find(item => item.peerId === connection.peer);
      remoteId = participant?.clientId;
      if (!remoteId || remoteId === this.clientId) { connection.close(); return; }
      const existing = this.connections.get(remoteId);
      if (existing && existing !== connection && existing.open) { connection.close(); return; }
      this.connections.set(remoteId, connection);
      this.callbacks.onPeerOpen(remoteId);
      this.inspectPath(connection);
    });
    if (remoteId && !this.connections.has(remoteId)) this.connections.set(remoteId, connection);
    connection.on('data', value => {
      if (!remoteId || this.connections.get(remoteId) !== connection || typeof value !== 'string' || value.length > 80000) return;
      try { this.callbacks.onPacket(JSON.parse(value), remoteId); }
      catch { this.callbacks.onNotice('A malformed peer frame was rejected.'); }
    });
    connection.on('close', () => {
      if (this.connections.get(remoteId) === connection) {
        this.connections.delete(remoteId);
        this.callbacks.onPeerClose(remoteId);
      }
      this.later(() => this.connectPeers(), 1500);
    });
    connection.on('error', () => connection.close());
    this.later(() => { if (!connection.open) { connection.close(); if (this.connections.get(remoteId) === connection) this.connections.delete(remoteId); this.connectPeers(); } }, 18000);
  }
  async inspectPath(connection) {
    try {
      const stats = await connection.peerConnection.getStats();
      let pair;
      stats.forEach(item => { if (item.type === 'transport' && item.selectedCandidatePairId) pair = stats.get(item.selectedCandidatePairId); });
      if (!pair) stats.forEach(item => { if (item.type === 'candidate-pair' && item.state === 'succeeded' && item.nominated) pair = item; });
      const local = pair && stats.get(pair.localCandidateId);
      const remote = pair && stats.get(pair.remoteCandidateId);
      this.callbacks.onPath(local?.candidateType === 'relay' || remote?.candidateType === 'relay' ? 'WebRTC via TURN' : pair ? 'WebRTC direct' : 'WebRTC data channel');
    } catch { this.callbacks.onPath('WebRTC data channel'); }
    this.later(() => { if (connection.open) this.inspectPath(connection); }, 10000);
  }
  async send(packet, to) {
    if (this.stopped) throw new Error('Session closed.');
    const encoded = JSON.stringify(packet);
    if (encoded.length > 76000) throw new Error('The encrypted packet exceeds the transport limit.');
    if (this.mode === 'relay') {
      if (this.ws?.readyState !== WebSocket.OPEN) throw new Error('The relay is reconnecting. Try again when connected.');
      await this.waitForBuffer(() => this.ws.bufferedAmount, () => this.ws.readyState === WebSocket.OPEN);
      this.ws.send(JSON.stringify({ type: 'packet', ...(to ? { to } : {}), packet }));
    } else {
      const connections = to ? [this.connections.get(to)] : [...this.connections.values()].filter(item => item.open);
      if (!connections.length || connections.some(item => !item?.open)) throw new Error('The other peer is disconnected. Messages remain in this browser until reconnection.');
      for (const connection of connections) {
        await this.waitForBuffer(() => connection.dataChannel?.bufferedAmount || 0, () => connection.open);
        connection.send(encoded);
      }
    }
  }
  async waitForBuffer(amount, isOpen) {
    const deadline = Date.now() + 30000;
    while (amount() > 256 * 1024) {
      if (this.stopped || !isOpen() || Date.now() > deadline) throw new Error('The connection stalled. Retry the transfer after reconnecting.');
      await delay(15);
    }
  }
  reconnect() { this.openDirectory(); this.connectPeers(); }
  close() {
    this.stopped = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    this.ws?.close();
    for (const connection of this.connections.values()) connection.close();
    this.connections.clear();
    this.peer?.destroy();
  }
}
