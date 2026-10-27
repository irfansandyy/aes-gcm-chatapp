import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { mkdir, writeFile, access, chmod } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const ipIndex = args.indexOf('--ip');
const ip = args[ipIndex + 1];
const turnInternalIndex = args.indexOf('--turn-internal-ip');
const turnInternalIp = turnInternalIndex >= 0 ? args[turnInternalIndex + 1] : '';
if (ipIndex < 0 || !isIP(ip ?? '') || (turnInternalIp && !isIP(turnInternalIp))) {
  console.error('Usage: node scripts/configure.mjs --ip <server-ip> [--turn-internal-ip <private-ip>]');
  process.exit(1);
}

async function writeNew(filename, text) {
  try { await access(filename); return false; } catch { /* Existing secrets are preserved. */ }
  await writeFile(filename, text, { mode: 0o600, flag: 'wx' });
  return true;
}

const secrets = path.join(root, '.secrets');
await mkdir(secrets, { recursive: true, mode: 0o700 });
await chmod(secrets, 0o700);
// Every generated key is 32 printable ASCII characters with 192 bits of entropy.
const masterKeys = { Alice: randomBytes(24).toString('base64'), Bob: randomBytes(24).toString('base64') };
await writeNew(path.join(secrets, 'kdc-keys.json'), `${JSON.stringify(masterKeys, null, 2)}\n`);
const secretFile = path.join(secrets, 'turn-secret');
await writeNew(secretFile, `${randomBytes(48).toString('hex')}\n`);
const { readFile } = await import('node:fs/promises');
const turnSecret = (await readFile(secretFile, 'utf8')).trim();
const externalIp = turnInternalIp ? `${ip}/${turnInternalIp}` : ip;
const turnConfiguration = [
  'listening-port=3478',
  'fingerprint',
  'use-auth-secret',
  `static-auth-secret=${turnSecret}`,
  'realm=cipher-room',
  `external-ip=${externalIp}`,
  ...(turnInternalIp ? [`relay-ip=${turnInternalIp}`] : []),
  'min-port=49160',
  'max-port=49200',
  'user-quota=8',
  'total-quota=128',
  'max-bps=20000000',
  'bps-capacity=200000000',
  'no-cli',
  'pidfile=/tmp/turnserver.pid',
  'no-auth-pings',
  'no-tls',
  'no-dtls',
  'no-multicast-peers',
  'denied-peer-ip=0.0.0.0-0.255.255.255',
  'denied-peer-ip=10.0.0.0-10.255.255.255',
  'denied-peer-ip=100.64.0.0-100.127.255.255',
  'denied-peer-ip=127.0.0.0-127.255.255.255',
  'denied-peer-ip=169.254.0.0-169.254.255.255',
  'denied-peer-ip=172.16.0.0-172.31.255.255',
  'denied-peer-ip=192.168.0.0-192.168.255.255',
  'denied-peer-ip=224.0.0.0-255.255.255.255',
  'denied-peer-ip=::1',
  'denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  'denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  'no-software-attribute',
  'log-file=/dev/null',
  'simple-log',
  'no-stdout-log',
].join('\n');
await writeNew(path.join(secrets, 'turnserver.conf'), `${turnConfiguration}\n`);
await writeNew(path.join(root, '.env'), [
  'APP_PORT=3000', 'PORT=3000', 'HOST=0.0.0.0', `PUBLIC_IP=${ip}`,
  'KDC_KEYS_FILE=.secrets/kdc-keys.json', 'KDC_STRICT_THREE_IPS=true',
  `TURN_PUBLIC_IP=${ip}`, 'TURN_PORT=3478', 'TURN_SECRET_FILE=.secrets/turn-secret',
  'STUN_URLS=', 'TRUST_PROXY=false', 'MAX_CLIENTS=256', 'MAX_ROOMS=128',
  'MAX_CLIENTS_PER_IP=12', 'SOCKET_FRAME_RATE=2000', '',
].join('\n'));
console.log('Configuration is ready. Existing files were preserved. No secrets were printed.');
console.log('Read .secrets/kdc-keys.json privately and give each participant only their own master key.');
console.log('Docker runs as UID 1000. Ensure UID 1000 can read the two mounted secret files.');
console.log('Start with: docker compose --profile turn up --build -d');
