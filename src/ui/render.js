import { icon } from './icons.js';

export const STATUS_LABELS = {
  idle: 'Not connected', deriving: 'Deriving encryption key', connecting: 'Connecting',
  waiting: 'Waiting for a participant', authenticating: 'Verifying session',
  ready: 'Connected', reconnecting: 'Reconnecting', error: 'Connection interrupted',
};

export const KDC_STEPS = [
  { step: 1, label: 'Alice requests a session key', detail: "Alice sends her identity, Bob's identity, and a fresh nonce to the KDC." },
  { step: 2, label: 'The KDC issues a session and ticket', detail: "The KDC protects the session key with Alice's master key and a ticket with Bob's master key." },
  { step: 3, label: "Alice delivers Bob's ticket", detail: 'Bob opens the ticket using his own master key.' },
  { step: 4, label: 'Bob sends a fresh challenge', detail: 'Bob encrypts a new nonce with the session key.' },
  { step: 5, label: 'Alice proves possession of the key', detail: 'Alice returns the transformed challenge. Both participants can now exchange encrypted messages.' },
];

export function text(element, value = '') {
  const content = String(value ?? '');
  if (element && element.textContent !== content) element.textContent = content;
}

export function visible(element, show) {
  if (!element) return;
  if (show) element.style.removeProperty('display');
  else element.style.display = 'none';
}

export function formatBytes(bytes = 0) {
  if (!bytes || !Number.isFinite(bytes) || bytes < 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  const index = Math.max(0, Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 3));
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatTime(time) {
  if (!time) return '';
  const date = new Date(time);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Templates below contain static application markup only. User-controlled text
// always enters through textContent or an attribute setter, never HTML parsing.
function createMessage(doc, message) {
  const node = doc.createElement('li');
  node.dataset.messageId = String(message.id);
  if (message.kind === 'system') {
    node.className = 'system-message';
    node.innerHTML = '<span></span><time></time>';
    return { node, kind: 'system', body: node.querySelector('span'), time: node.querySelector('time') };
  }
  node.className = 'message-row';
  node.innerHTML = `
    <div class="message-avatar" aria-hidden="true"></div>
    <div class="message-content">
      <div class="message-meta"><span><span class="sender-name"></span><small>You</small></span><time></time></div>
      <button type="button" class="message-bubble" data-action="select-message" aria-pressed="false"></button>
      <div class="message-footer"><span>${icon('lock-keyhole', 11)}<span class="message-status"></span></span><span class="message-timing"></span><button type="button" class="file-action" data-action="download-file">${icon('file', 13)}<span></span></button></div>
      <div class="message-progress"><progress max="100" value="0"></progress><span>0%</span></div>
    </div>`;
  const bubble = node.querySelector('.message-bubble');
  if (message.kind === 'file') {
    bubble.classList.add('file-bubble');
    bubble.innerHTML = `<span class="file-symbol">${icon('file', 21)}</span><span class="file-text"><strong></strong><span><span class="file-size"></span><span class="file-meta-divider">/</span><span class="file-status"></span></span></span>`;
  } else bubble.innerHTML = '<span class="message-text"></span>';
  const find = selector => node.querySelector(selector);
  return {
    node, kind: message.kind, bubble, avatar: find('.message-avatar'), name: find('.sender-name'),
    you: find('.message-meta small'), time: find('.message-meta time'), body: find('.message-text'),
    status: find('.message-status'), timing: find('.message-timing'), download: find('.file-action'),
    downloadLabel: find('.file-action > span'), progress: find('.message-progress'),
    progressBar: find('progress'), progressLabel: find('.message-progress > span'),
    fileName: find('.file-text strong'), fileSize: find('.file-size'), fileStatus: find('.file-status'),
  };
}

function updateMessage(entry, message, selected) {
  if (entry.previous === message && entry.selected === selected) return;
  entry.previous = message;
  entry.selected = selected;
  if (entry.kind === 'system') {
    text(entry.body, message.text);
    text(entry.time, formatTime(message.time));
    const date = new Date(message.time || Date.now());
    if (!Number.isNaN(date.getTime())) entry.time.dateTime = date.toISOString();
    return;
  }
  entry.node.classList.toggle('outgoing', Boolean(message.outgoing));
  entry.node.classList.toggle('selected', Boolean(selected));
  const name = message.senderName || 'Participant';
  text(entry.avatar, (message.senderName || 'Guest').slice(0, 1).toUpperCase());
  text(entry.name, name);
  visible(entry.you, message.outgoing);
  text(entry.time, formatTime(message.time));
  entry.bubble.setAttribute('aria-pressed', String(Boolean(selected)));
  const file = message.file;
  entry.bubble.setAttribute('aria-label', file ? `Inspect file ${file.name}` : `Inspect message from ${name}`);
  if (file) {
    text(entry.fileName, file.name);
    text(entry.fileSize, formatBytes(file.size));
    text(entry.fileStatus, file.status === 'complete' ? 'Complete' : file.status === 'offered' ? 'Ready to receive' : file.status);
  } else text(entry.body, message.text);
  const queued = message.queued || message.crypto?.localOnly;
  text(entry.status, message.recovered ? 'Recovered from peer' : queued ? 'Waiting for peer' : 'Encrypted');
  const measured = message.crypto?.elapsedMs !== undefined;
  visible(entry.timing, measured);
  if (measured) text(entry.timing, `${Number(message.crypto.elapsedMs).toFixed(1)} ms`);
  const incomingOffer = file && !file.available && ['offered', 'interrupted', 'cancelled'].includes(file.status) && !message.outgoing;
  visible(entry.download, file && (file.available || incomingOffer));
  text(entry.downloadLabel, incomingOffer ? 'Receive file' : 'Download');
  const transferring = file && ['sending', 'receiving'].includes(file.status);
  visible(entry.progress, transferring);
  if (transferring) {
    entry.progressBar.value = file.progress || 0;
    entry.progressBar.setAttribute('aria-label', `${file.name} transfer progress`);
    text(entry.progressLabel, `${Math.floor(file.progress || 0)}%`);
  }
}

export function createMessageRenderer(doc, list) {
  const entries = new Map();
  return {
    update(messages, selectedId) {
      const current = new Set();
      let position = list.firstElementChild;
      for (const message of messages) {
        const id = String(message.id);
        current.add(id);
        let entry = entries.get(id);
        if (!entry || entry.kind !== message.kind) {
          entry?.node.remove();
          entry = createMessage(doc, message);
          entries.set(id, entry);
        }
        updateMessage(entry, message, id === selectedId);
        if (entry.node !== position) list.insertBefore(entry.node, position);
        position = entry.node.nextElementSibling;
      }
      for (const [id, entry] of entries) {
        if (!current.has(id)) { entry.node.remove(); entries.delete(id); }
      }
    },
    clear() { for (const entry of entries.values()) entry.node.remove(); entries.clear(); },
  };
}

export function createExchangeRenderer(doc, list) {
  const entries = KDC_STEPS.map(base => {
    const node = doc.createElement('li');
    node.innerHTML = '<span class="step-number"></span><div><div class="step-heading"><h3></h3><span></span></div><p></p><details class="envelope-detail"><summary>Inspect encrypted envelope</summary><pre></pre></details></div>';
    list.append(node);
    return { node, number: node.querySelector('.step-number'), label: node.querySelector('h3'), status: node.querySelector('.step-heading > span'), detail: node.querySelector('p'), envelope: node.querySelector('details'), data: node.querySelector('pre'), state: null, base };
  });
  return exchange => {
    let completed = 0;
    for (const entry of entries) {
      const step = { ...entry.base, ...exchange?.find(item => item.step === entry.base.step) };
      const state = step.state || 'pending';
      if (state === 'complete') completed++;
      entry.node.className = `exchange-step ${state === 'complete' ? 'complete' : state === 'failed' ? 'failed' : 'pending'}`;
      if (entry.state !== state) {
        if (state === 'complete') entry.number.innerHTML = icon('check', 15);
        else text(entry.number, step.step);
        entry.state = state;
      }
      text(entry.label, step.label);
      text(entry.status, state === 'complete' ? 'Verified' : state === 'failed' ? 'Failed' : 'Pending');
      text(entry.detail, step.detail);
      visible(entry.envelope, Boolean(step.envelope));
      text(entry.data, step.envelope ? typeof step.envelope === 'string' ? step.envelope : JSON.stringify(step.envelope, null, 2) : '');
    }
    return completed;
  };
}

export function createParticipantRenderer(doc, list) {
  let lastSignature = '';
  return (participants, clientId) => {
    const signature = JSON.stringify([participants, clientId]);
    if (lastSignature === signature) return;
    lastSignature = signature;
    const nodes = participants.map(person => {
      const node = doc.createElement('li');
      node.innerHTML = '<span class="participant-avatar"></span><span><strong><span></span><small>You</small></strong><span class="mono"></span></span><span class="presence-dot" title="Connected"></span>';
      const name = person.identity || person.role || 'Guest';
      text(node.querySelector('.participant-avatar'), name.slice(0, 1).toUpperCase());
      text(node.querySelector('strong > span'), name);
      visible(node.querySelector('small'), person.clientId === clientId);
      text(node.querySelector('.mono'), person.ip || 'Address unavailable');
      return node;
    });
    list.replaceChildren(...nodes);
  };
}
