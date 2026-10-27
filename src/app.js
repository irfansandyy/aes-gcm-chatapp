import { CipherSession, initialState } from './client/session.js';
import { hydrateIcons, setIcon } from './ui/icons.js';
import {
  STATUS_LABELS, text, visible, formatBytes,
  createMessageRenderer, createExchangeRenderer, createParticipantRenderer,
} from './ui/render.js';

export function createDashboard(doc, sessionFactory = onChange => new CipherSession(onChange)) {
  const win = doc.defaultView || globalThis;
  const root = doc.querySelector('[data-dashboard]');
  if (!root) throw new Error('The dashboard HTML is missing.');
  const refs = Object.fromEntries([...root.querySelectorAll('[id]')].map(element => [element.id, element]));
  const listen = (element, event, handler) => {
    element.addEventListener(event, handler);
    cleanup.push(() => element.removeEventListener(event, handler));
  };
  const cleanup = [];
  const timers = new Set();
  const requestFrame = win.requestAnimationFrame?.bind(win) || (callback => win.setTimeout(callback, 0));
  const cancelFrame = win.cancelAnimationFrame?.bind(win) || win.clearTimeout.bind(win);
  let frame = null;
  let destroyed = false;
  let state = initialState();
  let mode = 'relay';
  let tab = 'conversation';
  let secretVisible = false;
  let sending = false;
  let dragging = false;
  let localError = '';
  let composeError = '';
  let lastMessageCount = 0;
  let uiGeneration = 0;
  let canCompose = false;
  let ready = false;
  let joined = false;
  let activeTransfer = false;
  let previousMode = '';
  const messageRenderer = createMessageRenderer(doc, refs['message-list']);
  const updateExchange = createExchangeRenderer(doc, refs['exchange-list']);
  const updateParticipants = createParticipantRenderer(doc, refs['participant-list']);
  const hexValues = {};
  hydrateIcons(root);

  const schedule = () => {
    if (destroyed || frame !== null) return;
    frame = requestFrame(() => { frame = null; render(); });
  };
  const session = sessionFactory(next => { state = next; schedule(); });
  if (session.state) state = session.state;

  function setSetup(open) {
    refs['session-sidebar'].classList.toggle('mobile-open', open);
    visible(refs['sidebar-scrim'], open);
  }
  function setError(message, local = false) {
    if (local) localError = message;
    else composeError = message;
    schedule();
  }
  function clearSensitiveFields() {
    refs['shared-secret'].value = '';
    refs['master-key'].value = '';
    refs['message-input'].value = '';
    refs['file-input'].value = '';
    text(refs['revealed-key'], '');
    visible(refs['revealed-key'], false);
  }
  function leave() {
    uiGeneration++;
    session.leave();
    clearSensitiveFields();
    localError = '';
    composeError = '';
    sending = false;
    dragging = false;
    schedule();
  }
  function optionsFromForm() {
    return {
      room: refs['room-name'].value, identity: refs['display-name'].value,
      secret: refs['shared-secret'].value, mode, keyMode: refs['key-method'].value,
      role: refs['kdc-role'].value, masterKey: refs['master-key'].value,
      forceRelay: refs['force-relay'].checked,
    };
  }
  async function join(event) {
    event.preventDefault();
    localError = '';
    composeError = '';
    const options = optionsFromForm();
    if (!/^[\x20-\x7e]+$/.test(options.identity)) {
      setError('Use printable ASCII characters for your display name.', true);
      return;
    }
    const generation = ++uiGeneration;
    try {
      await session.join(options);
      if (generation === uiGeneration && !destroyed) setSetup(false);
    } catch (error) {
      if (generation === uiGeneration && !destroyed) setError(error.message || 'Could not join this room.', true);
    }
    schedule();
  }
  async function send() {
    const input = refs['message-input'];
    const draft = input.value;
    if (!draft.trim() || !canCompose || sending) return;
    if (/[^\x09\x0a\x0d\x20-\x7e]/.test(draft)) {
      setError('Messages must use ASCII characters. Remove accented characters and symbols outside ASCII.');
      return;
    }
    const generation = uiGeneration;
    sending = true;
    composeError = '';
    schedule();
    try {
      await session.sendText(draft);
      if (generation === uiGeneration && input.value === draft) input.value = '';
    } catch (error) {
      if (generation === uiGeneration) composeError = error.message || 'Could not send this message.';
    } finally {
      if (generation === uiGeneration) sending = false;
      schedule();
    }
  }
  async function sendFile(file) {
    dragging = false;
    schedule();
    if (!file || !canCompose) return;
    if (file.size > 1073741824) { setError('The maximum file size is 1 GiB.'); return; }
    composeError = '';
    const generation = uiGeneration;
    try { await session.sendFile(file); }
    catch (error) { if (generation === uiGeneration) setError(error.message || 'Could not transfer this file.'); }
    schedule();
  }
  async function download(id) {
    try { await session.downloadFile(id); }
    catch (error) { setError(error.message || 'This file is not available.'); }
  }
  function reconnect() {
    session.emit({ error: '' });
    session.transport?.reconnect();
    if (session.options?.keyMode === 'kdc' && session.options.role === 'Alice' && !session.state.key) {
      session.handshakeStarted = false;
      const bob = session.state.participants.find(item => item.role === 'Bob');
      if (bob) session.onPeerOpen(bob.clientId).catch(error => session.notice(error));
    }
  }
  async function copy(field, button) {
    const value = hexValues[field];
    if (!value || !win.navigator.clipboard?.writeText) return;
    try {
      await win.navigator.clipboard.writeText(value);
      setIcon(button.querySelector('svg'), 'check');
      const timer = win.setTimeout(() => { timers.delete(timer); if (!destroyed) setIcon(button.querySelector('svg'), 'copy'); }, 1800);
      timers.add(timer);
    } catch { setIcon(button.querySelector('svg'), 'copy'); }
  }

  listen(refs['session-form'], 'submit', join);
  listen(refs['session-form'], 'input', () => { localError = ''; schedule(); });
  listen(refs['session-form'], 'change', () => { localError = ''; schedule(); });
  listen(refs['message-input'], 'input', () => { composeError = ''; schedule(); });
  listen(refs['message-input'], 'keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); send(); }
  });
  listen(refs['file-input'], 'change', event => {
    sendFile(event.target.files?.[0]);
    event.target.value = '';
  });
  listen(refs['conversation-log'], 'dragover', event => {
    if (canCompose && [...event.dataTransfer.types].includes('Files')) { event.preventDefault(); dragging = true; schedule(); }
  });
  listen(refs['conversation-log'], 'dragleave', event => {
    if (!event.currentTarget.contains(event.relatedTarget)) { dragging = false; schedule(); }
  });
  listen(refs['conversation-log'], 'drop', event => { event.preventDefault(); sendFile(event.dataTransfer.files?.[0]); });
  listen(root, 'click', event => {
    const button = event.target.closest('button');
    if (!button || button.disabled || !root.contains(button)) return;
    if (button.dataset.mode) { mode = button.dataset.mode; localError = ''; schedule(); return; }
    if (button.dataset.tab) { tab = button.dataset.tab; schedule(); return; }
    if (button.dataset.copy) { copy(button.dataset.copy, button); return; }
    const action = button.dataset.action;
    if (action === 'open-setup') setSetup(true);
    else if (action === 'close-setup') setSetup(false);
    else if (action === 'leave') leave();
    else if (action === 'send') send();
    else if (action === 'attach') refs['file-input'].click();
    else if (action === 'cancel-transfer') session.cancelTransfer();
    else if (action === 'forget-history') session.forgetHistory();
    else if (action === 'dismiss-error') session.emit({ error: '' });
    else if (action === 'reconnect') reconnect();
    else if (action === 'toggle-key') session.emit({ keyRevealed: !state.keyRevealed });
    else if (action === 'toggle-secret') { secretVisible = !secretVisible; schedule(); }
    else if (action === 'select-message') {
      const id = button.closest('[data-message-id]')?.dataset.messageId;
      session.emit({ selectedMessage: state.messages.find(message => message.id === id) || null });
    } else if (action === 'download-file') download(button.closest('[data-message-id]')?.dataset.messageId);
  });
  listen(win, 'pagehide', () => { leave(); render(); });

  function updateHex(name, value) {
    const field = root.querySelector(`[data-hex="${name}"]`);
    const string = typeof value === 'string' ? value : '';
    hexValues[name] = string;
    const pre = field.querySelector('pre');
    text(pre, string || 'Available after encryption');
    pre.classList.toggle('hex-empty', !string);
    visible(field.querySelector('button'), Boolean(string && win.navigator.clipboard?.writeText));
    if (name === 'aad') visible(field, Boolean(string));
  }

  function render() {
    if (destroyed) return;
    const status = state.status || 'idle';
    const busy = ['deriving', 'connecting', 'authenticating'].includes(status);
    joined = !['idle', 'error'].includes(status);
    ready = status === 'ready';
    canCompose = ready || status === 'waiting' && Boolean(state.key) && (state.keyMode === 'shared' || state.exchange?.find(step => step.step === 5)?.state === 'complete');
    const effectiveMode = joined || busy ? state.mode : mode;
    const keyMode = joined || busy ? state.keyMode : refs['key-method'].value;
    const p2p = effectiveMode === 'p2p';
    const kdc = keyMode === 'kdc';
    const messages = state.messages || [];
    const participants = state.participants || [];
    const selectedId = typeof state.selectedMessage === 'string' ? state.selectedMessage : state.selectedMessage?.id;
    const selected = messages.find(message => message.id === selectedId) || (typeof state.selectedMessage === 'object' ? state.selectedMessage : null);
    const crypto = selected?.crypto;
    activeTransfer = Boolean(state.transfer && ['sending', 'receiving', 'send', 'receive', 'active'].includes(state.transfer.status || state.transfer.direction));

    for (const id of ['room-name', 'display-name', 'key-method']) refs[id].disabled = joined || busy;
    refs['shared-secret'].disabled = joined || busy || kdc;
    refs['shared-secret'].required = !kdc;
    refs['master-key'].disabled = joined || busy || !kdc;
    refs['master-key'].required = kdc;
    refs['kdc-role'].disabled = joined || busy || !kdc;
    refs['force-relay'].disabled = joined || busy;
    visible(refs['shared-secret-field'], !kdc);
    visible(refs['kdc-role-field'], kdc);
    visible(refs['master-key-field'], kdc);
    visible(refs['connection-options'], p2p);
    visible(refs['join-button'], !joined);
    visible(refs['leave-button'], joined);
    visible(refs['session-hint'], joined);
    refs['join-button'].disabled = busy;
    setIcon(refs['join-button'].querySelector('svg'), busy ? 'loader-circle' : 'lock-keyhole');
    refs['join-button'].querySelector('svg').classList.toggle('spinning', busy);
    text(refs['join-button'].querySelector('span'), busy ? STATUS_LABELS[status] : 'Join room');
    for (const id of ['shared-secret', 'master-key']) refs[id].type = secretVisible ? 'text' : 'password';
    for (const button of root.querySelectorAll('[data-action="toggle-secret"]')) {
      const master = button.closest('label').id === 'master-key-field';
      button.setAttribute('aria-label', `${secretVisible ? 'Hide' : 'Show'} ${master ? 'master key' : 'encryption secret'}`);
      setIcon(button.querySelector('svg'), secretVisible ? 'eye-off' : 'eye');
    }
    visible(refs['local-error'], localError);
    text(refs['local-error'], localError);
    for (const button of root.querySelectorAll('[data-mode]')) {
      button.disabled = joined || busy;
      button.classList.toggle('active', button.dataset.mode === effectiveMode);
      button.setAttribute('aria-pressed', String(button.dataset.mode === effectiveMode));
    }
    text(refs['transport-description'], p2p ? 'Direct when possible. Encrypted at every hop.' : 'One room for everyone with the secret.');
    refs['connection-status'].className = `connection-status status-${Object.hasOwn(STATUS_LABELS, status) ? status : 'idle'}`;
    refs['connection-status'].querySelector('.presence-dot').classList.toggle('muted', !ready);
    text(refs['connection-status'].querySelector('span:last-child'), STATUS_LABELS[status] || status);
    visible(refs['error-banner'], state.error);
    text(refs['session-error'], state.error);
    visible(refs['reconnect-button'], ['error', 'reconnecting'].includes(status));
    text(refs['room-title'], joined || busy ? state.room || refs['room-name'].value : 'Your room');
    text(refs['room-subtitle'], joined ? `${participants.length} participant${participants.length === 1 ? '' : 's'} in this session` : 'Set up a session to get started');

    for (const button of root.querySelectorAll('[data-tab]')) {
      const active = button.dataset.tab === tab;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    for (const panel of root.querySelectorAll('[data-view]')) visible(panel, panel.dataset.view === tab);
    visible(refs['empty-conversation'], messages.length === 0);
    visible(refs['conversation-start'], messages.length > 0);
    visible(refs['message-list'], messages.length > 0);
    visible(refs['drop-overlay'], dragging);
    refs['conversation-log'].classList.toggle('dragging', dragging);
    text(refs['empty-title'], joined ? 'Your room is ready.' : 'Start a private conversation.');
    text(refs['empty-description'], joined ? ready ? 'Send your first message or share a file. Select any message to inspect its encryption.' : kdc ? 'Open this room on the other device. Choose the other classroom identity and enter its own master key.' : 'Open this app on another device. Use the same room and secret to connect automatically.' : 'Choose a room name and an encryption secret. Give both to the people you want to talk with.');
    if (previousMode !== effectiveMode) {
      setIcon(refs['empty-transport'].querySelector('svg'), p2p ? 'network' : 'radio');
      text(refs['empty-transport'].querySelector('span'), p2p ? 'WebRTC data channel' : 'Encrypted room relay');
      setIcon(refs['notes-transport-icon'], p2p ? 'network' : 'radio');
      text(refs['history-note'], p2p ? 'A connected peer keeps a bounded history in memory and synchronizes it when a participant returns. When all peers disconnect, that history is gone.' : 'The relay forwards encrypted packets and keeps no conversation history. Messages displayed in your browser disappear when you leave or close it.');
      text(refs['notes-transport-title'], p2p ? 'PeerJS, WebRTC, STUN, and TURN' : 'WebSocket room relay');
      text(refs['notes-transport-description'], p2p ? 'PeerJS exchanges connection information automatically. STUN discovers connection candidates. WebRTC carries encrypted data directly when possible; your self-hosted TURN server forwards packets when a direct route fails.' : 'Every browser maintains a WebSocket connection to your server. The server delivers encrypted packets to other participants in the same room. Room names and connection metadata are visible to the server.');
      previousMode = effectiveMode;
    }
    const log = refs['conversation-log'];
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 100;
    messageRenderer.update(messages, selectedId);
    if (messages.length !== lastMessageCount && tab === 'conversation' && (nearBottom || messages.at(-1)?.outgoing)) {
      log.scrollTop = log.scrollHeight;
    }
    lastMessageCount = messages.length;

    visible(refs['transfer-bar'], activeTransfer);
    if (activeTransfer) {
      text(refs['transfer-name'], state.transfer.name);
      text(refs['transfer-percent'], `${Math.floor(state.transfer.progress || 0)}%`);
      refs['transfer-progress'].value = state.transfer.progress || 0;
      const description = refs['transfer-description'];
      const direction = `${state.transfer.direction === 'receive' ? 'Receiving' : 'Sending'} encrypted chunks`;
      if (description.firstChild.nodeValue !== direction) description.firstChild.nodeValue = direction;
      const size = formatBytes(state.transfer.size);
      if (description.lastChild.nodeValue !== size) description.lastChild.nodeValue = size;
    }
    visible(refs['compose-error'], composeError);
    text(refs['compose-error'], composeError);
    refs['composer'].classList.toggle('composer-disabled', !canCompose);
    refs['message-input'].disabled = !canCompose;
    refs['message-input'].placeholder = canCompose ? ready ? 'Write an encrypted message...' : 'Write a message for your returning peer...' : joined ? 'Waiting for a secure connection...' : 'Join a room to start a conversation...';
    refs['attach-button'].disabled = !canCompose || activeTransfer;
    refs['send-button'].disabled = !canCompose || !refs['message-input'].value.trim() || sending;
    text(refs['send-button'].querySelector('span'), sending ? 'Encrypting' : 'Send');
    text(refs['character-count'], `${refs['message-input'].value.length.toLocaleString()} / 8,000`);
    text(refs['composer-privacy'], canCompose && !ready ? 'Messages stay in memory until your peer returns.' : 'Only participants with the key can read your messages.');
    refs['clear-history-button'].disabled = messages.length === 0;
    text(refs['footer-transport'], p2p ? 'Peer-to-peer session' : 'Room relay session');
    text(refs['footer-fingerprint'], state.fingerprint ? `Key ${state.fingerprint.slice(0, 14)}` : 'No key established');

    text(refs['exchange-count'], `${updateExchange(state.exchange)} / 5 complete`);
    const alice = participants.find(person => person.role?.toLowerCase() === 'alice');
    const bob = participants.find(person => person.role?.toLowerCase() === 'bob');
    text(refs['alice-address'], alice?.ip || (state.identity === 'Alice' ? state.connection?.localIp : '') || 'Separate device');
    text(refs['bob-address'], bob?.ip || (state.identity === 'Bob' ? state.connection?.localIp : '') || 'Separate device');
    text(refs['kdc-address'], state.connection?.serverIp || 'Your server');
    visible(refs['shared-key-note'], !kdc);
    visible(refs['strict-ip-note'], kdc && state.config?.kdc?.strictThreeIps === false);

    text(refs['inspector-transport'], p2p ? 'WebRTC' : 'WebSocket');
    text(refs['inspector-key-source'], kdc ? 'KDC session key' : 'Shared secret');
    text(refs['inspector-fingerprint'], state.fingerprint || 'Not established');
    visible(refs['demo-key'], state.key);
    visible(refs['revealed-key'], state.key && state.keyRevealed);
    text(refs['revealed-key'], state.key && state.keyRevealed ? state.key : '');
    text(refs['reveal-key-button'].querySelector('span'), state.keyRevealed ? 'Hide session key' : 'Reveal session key');
    setIcon(refs['reveal-key-button'].querySelector('svg'), state.keyRevealed ? 'eye-off' : 'eye');
    if (!state.key) refs['demo-key'].open = false;
    visible(refs['selected-packet'], selected);
    visible(refs['no-packet'], !selected);
    visible(refs['packet-kind'], selected);
    text(refs['packet-kind'], selected?.kind === 'file' ? 'File chunk' : 'Text');
    text(refs['plaintext-length'], formatBytes(crypto?.plaintextBytes));
    text(refs['ciphertext-length'], formatBytes(crypto?.ciphertextBytes));
    text(refs['processing-time'], crypto?.elapsedMs !== undefined ? `${Number(crypto.elapsedMs).toFixed(2)} ms` : 'Not measured');
    text(refs['packet-id'], crypto?.packetId || selected?.id || '');
    updateHex('iv', crypto?.iv);
    updateHex('tag', crypto?.tag);
    updateHex('ciphertext', crypto?.ciphertext);
    updateHex('aad', typeof crypto?.aad === 'string' ? crypto.aad : crypto?.aad ? JSON.stringify(crypto.aad) : '');
    text(refs['ciphertext-hint'], crypto?.truncated ? 'Ciphertext is truncated for the inspector. The complete packet was authenticated before display.' : crypto?.localOnly ? 'Encrypted locally while waiting for a peer. Delivery begins when a participant reconnects.' : selected?.kind === 'file' ? 'A sample chunk is shown. File data is encrypted chunk by chunk.' : 'Select a different message to compare its IV and ciphertext.');
    text(refs['connection-path'], state.connection?.path || 'Not connected');
    text(refs['local-address'], state.connection?.localIp || 'Not connected');
    text(refs['server-address'], state.connection?.serverIp || 'Not connected');
    visible(refs['turn-configured-row'], p2p);
    text(refs['turn-configured'], state.connection?.turnConfigured ? 'Yes' : 'No');
    text(refs['participant-count'], participants.length);
    visible(refs['participant-list'], participants.length > 0);
    visible(refs['no-participants'], participants.length === 0);
    updateParticipants(participants, state.clientId);
  }

  function renderNow() {
    if (frame !== null) { cancelFrame(frame); frame = null; }
    render();
  }
  renderNow();
  return {
    session,
    renderNow,
    destroy() {
      if (destroyed) return;
      leave();
      destroyed = true;
      if (frame !== null) cancelFrame(frame);
      for (const timer of timers) win.clearTimeout(timer);
      for (const remove of cleanup) remove();
      messageRenderer.clear();
    },
  };
}

if (typeof document !== 'undefined' && document.querySelector('[data-dashboard]') && !globalThis.__CIPHERROOM_DISABLE_AUTOSTART__) {
  createDashboard(document);
}
