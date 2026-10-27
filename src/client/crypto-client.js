export class CryptoClient {
  constructor() {
    this.worker = new Worker(new URL('./crypto-worker.js', import.meta.url), { type: 'module' });
    this.pending = new Map();
    this.nextId = 1;
    this.worker.onmessage = ({ data }) => {
      const pending = this.pending.get(data.id);
      if (!pending) return;
      this.pending.delete(data.id);
      if (data.error) pending.reject(new Error(data.error));
      else pending.resolve(data.result);
    };
    this.worker.onerror = () => this.close('The encryption worker stopped. Leave and join the room again.');
  }
  call(op, ...args) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, op, args });
    });
  }
  close(reason = 'Session closed.') {
    this.worker.terminate();
    for (const pending of this.pending.values()) pending.reject(new Error(reason));
    this.pending.clear();
  }
}
