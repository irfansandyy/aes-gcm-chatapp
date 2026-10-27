import * as cryptoTools from '../shared/crypto.js';

let sessionKey = '';
self.onmessage = ({ data: { id, op, args = [] } }) => {
  try {
    let result;
    if (op === 'derive') result = cryptoTools.deriveRoomKey(...args);
    else if (op === 'setKey') { cryptoTools.validateKey(args[0]); sessionKey = args[0]; result = cryptoTools.fingerprint(sessionKey); }
    else if (op === 'seal') result = cryptoTools.seal(sessionKey, cryptoTools.encodeJson(args[0]), args[1]);
    else if (op === 'open') result = cryptoTools.decodeJson(cryptoTools.open(sessionKey, args[0], args[1]));
    else if (op === 'openWithKey') result = cryptoTools.decodeJson(cryptoTools.open(args[0], args[1], args[2]));
    else if (op === 'sealWithKey') result = cryptoTools.seal(args[0], cryptoTools.encodeJson(args[1]), args[2]);
    else throw new Error('Unknown cryptographic operation.');
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: error.message });
  }
};
