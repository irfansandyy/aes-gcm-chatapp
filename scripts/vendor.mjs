import { copyFile, mkdir, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Copy only the support modules used by the app. AES, GHASH, and GCM stay in our source.
const packages = [
  {
    name: '@noble/hashes',
    version: '2.4.0',
    files: ['sha2.js', '_md.js', '_u64.js', 'pbkdf2.js', 'hmac.js', 'utils.js', 'LICENSE'],
  },
  {
    name: '@scure/base',
    version: '2.4.0',
    files: ['index.js', 'LICENSE'],
  },
];

export async function prepareVendor() {
  // Validate the installed versions before replacing the generated directory.
  for (const dependency of packages) {
    const metadata = JSON.parse(await readFile(path.join(root, 'node_modules', dependency.name, 'package.json'), 'utf8'));
    if (metadata.version !== dependency.version) {
      throw new Error(`Expected ${dependency.name}@${dependency.version}, found ${metadata.version}. Run npm ci.`);
    }
  }

  const destination = path.join(root, 'vendor');
  await rm(destination, { recursive: true, force: true });
  for (const dependency of packages) {
    const directory = path.join(destination, dependency.name);
    await mkdir(directory, { recursive: true });
    for (const filename of dependency.files) {
      await copyFile(path.join(root, 'node_modules', dependency.name, filename), path.join(directory, filename));
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await prepareVendor();
  console.log('Copied Base64, SHA-256, HMAC, PBKDF2, and licenses into vendor/.');
}
