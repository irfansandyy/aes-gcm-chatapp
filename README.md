# Cipher Room

Accountless encrypted chat and file transfer for a university information security demonstration. The application has a dark browser dashboard, two communication modes, two key methods, a manual AES implementation, and the five-step KDC scenario from the supplied lecture material. All source code and documentation are in English.

The browser interface uses plain HTML, CSS, and JavaScript ES modules. The existing dashboard layout and CSS animations are kept in the source. Browser DOM events connect the controls to the session logic; there is no UI framework or frontend transpilation. Node.js, Express, PeerJS, WebSocket, and coturn still provide the required server and networking services.

| Choice | Behavior |
| --- | --- |
| Room relay | A memory-only server forwards encrypted packets. Shared-secret rooms support up to 32 participants. |
| Peer to peer | Two browsers discover each other automatically, then exchange application packets through a WebRTC data channel. PeerJS provides signaling; STUN and self-hosted TURN provide connectivity. |
| Shared secret | Enter the same room and ASCII secret on each device. The browsers derive the same key locally. The server receives neither the secret nor the derived key. |
| Lecturer KDC | Alice and Bob enter their own master keys. The KDC creates and distributes a fresh session key, and the clients complete the five-step challenge-response exchange before messaging. |

Display names are labels, not verified identities. There are no accounts, login screens, cookies, or chat database. A secret establishes membership, not personal identity. The KDC deliberately knows the session keys it creates.

## Quick start

Use Node.js 22.12 or newer and npm. Replace `192.168.1.10` with the actual reachable server IP.

```sh
npm install
npm run configure -- --ip 192.168.1.10
npm run dev
```

Open `http://192.168.1.10:3000` on each device. One Node process serves the interface, API, relay, KDC, and signaling on the same port. Development mode watches the server for changes. After editing browser HTML, CSS, or JavaScript, refresh the browser to load the updated source.

For a production process without the development watcher:

```sh
npm start
```

The server serves the source files directly, so no frontend build is required. Configuration is in `.env`; secrets are in `.secrets/`. Review the deployment notes before exposing the server publicly. The app opens at `/`.

## Browser source and optional static export

Edit the page structure in `index.html`, the appearance and animations in `src/styles.css`, and the controls in `src/app.js`. Dynamic messages and inspector panels are rendered by `src/ui/render.js`. The browser loads JavaScript through native `type="module"` imports and loads the encryption worker as a separate module. Refresh the browser after edits; there is no hot reload or separate frontend development server.

`npm run build` is an optional asset-copying command. It prepares the pinned support-library modules, then copies the HTML, CSS, JavaScript, public files, support libraries, licenses, and local PeerJS browser asset into `dist/`. It does not compile, bundle, minify, or transpile the source. Normal `npm start` and Docker hosting continue to serve source files, even if `dist/` exists. To serve an exported copy deliberately, set `STATIC_DIR=dist` in `.env` and restart the server. Export again after changing browser files when using that option.

The install step runs `scripts/vendor.mjs`, which copies the pinned support-library modules and licenses from installed packages into `vendor/`. Node, browsers, and the module worker use those same local ES modules. These are local copies of the installed npm packages. Browser modules cannot import Node's `node:crypto`, and this HTTP application does not depend on `crypto.subtle`, so the portable JavaScript packages supply SHA-256, PBKDF2/HMAC, and Base64 in all three environments. If install scripts were deliberately skipped, run `node scripts/vendor.mjs` before configuring or starting the app. No external CDN is used.

PeerJS's browser library is served locally at `/vendor/peerjs.min.js` from the installed npm package. Its `Peer` global is used by the native transport module. The SVG icons use the existing official Lucide paths stored in `public/icons.svg`, with the license alongside the asset. No icon font, emoji, remote icon request, or UI-framework runtime is required.

## Docker deployment

Docker Engine with Compose is required. The TURN profile uses Linux host networking.

```sh
npm run configure -- --ip 203.0.113.10
docker compose --profile turn up --build -d
```

The example public address is documentation only. Substitute your real public IP. If the host is behind NAT, include its real private interface address during initial configuration:

```sh
npm run configure -- --ip 203.0.113.10 --turn-internal-ip 192.168.1.10
```

The configuration command preserves existing files. It does not overwrite secrets or silently change an existing deployment to a new IP. Edit `.env` and `.secrets/turnserver.conf` deliberately when changing network addresses. Keep their TURN secret values consistent.

Allow TCP 3000 for HTTP, UDP and TCP 3478 for STUN/TURN, and UDP 49160 through 49200 for TURN relay allocations. Port mappings, public routing, and any cloud firewall must agree. TURN is needed for difficult NATs and restrictive networks; merely starting the app container does not create a working TURN service. The default TURN configuration prevents relaying to private address ranges. Use the trusted LAN for direct LAN testing and public endpoints for a forced TURN demonstration.

The app runs as UID 1000 in its container. Ensure UID 1000 can read the mounted KDC and TURN secret files while keeping them private. Do not make them world-readable. The app filesystem is read-only; temporary process data is held in a small temporary memory filesystem. Docker and TURN may keep operational logs depending on deployment settings; the application does not write chat contents to logs.

See [deployment instructions](deploy/README.md) for firewall checks, NAT setup, and the environment variables.

## IP-only HTTP hosting

Open `http://<server-ip>:3000` on each device. The application uses HTTP and ordinary WebSocket for the dashboard, API, relay, and PeerJS signaling. No domain name or certificate installation is needed.

Cryptography uses `crypto.getRandomValues()` for randomness. The manual AES code and the JavaScript support libraries do not depend on `crypto.subtle`. The application uses data channels only, with no camera or microphone permission. A Chrome test on an ordinary non-loopback IP HTTP origin successfully derived a key, connected WebRTC directly, and delivered encrypted text without security flags or a warning bypass. WebRTC availability is detected at runtime because browser and managed-device policies can differ. If a browser blocks the required capability, use room relay on that device.

## Three-device KDC demonstration

Use three devices with three distinct server-observed IP addresses: KDC/server, Alice, and Bob. On a LAN, an example is server `192.168.1.10`, Alice `192.168.1.11`, Bob `192.168.1.12`. Both clients must reach the server, join the same transport and KDC room, choose different roles, and enter their own master keys.

The configuration command creates different 32-character ASCII master keys in `.secrets/kdc-keys.json`. Give Alice only Alice's key and Bob only Bob's key through a private, trusted channel. The server rereads this file for each new KDC request, so keys can be changed without restarting the server. For Docker bind mounts, edit the existing file in place; an editor that replaces its inode can require a container restart. Rejoin or start a new handshake with matching client keys after changing them.

`KDC_STRICT_THREE_IPS=true` is the default and enforces the address requirement. Two devices sharing a public NAT address appear as the same IP to a remote server and will fail this check. Use the LAN setup, distinct public network paths, or routed networks that preserve distinct source addresses. Setting this flag to `false` is useful only for local development and does not satisfy the three-address assignment requirement.

## Encryption and file limits

AES key expansion and block rounds remain manual, including SubBytes, ShiftRows, MixColumns, and AddRoundKey. Project code also implements all GCM operations, including counter mode, GHASH finite-field hashing, IV handling, authentication tags, and tag verification, and implements the five-step KDC. Supporting operations use pinned standard libraries:

| Operation | Implementation |
| --- | --- |
| AES blocks and key expansion | Manual project source |
| GCM counter/XOR, AES-derived hash subkey, length block, tag assembly, and verification | Project source |
| GHASH finite-field hashing and padding | Manual project source |
| SHA-256 and PBKDF2-HMAC-SHA-256 | `@noble/hashes` 2.4.0; PBKDF2 uses its HMAC implementation internally |
| Base64 encoding and decoding | `@scure/base` 2.4.0 |
| KDC tickets, nonces, key distribution, and five-step validation | Manual project source |

AES and the complete GCM construction, including GHASH, use the project's manual source. WebRTC's additional transport encryption is supplied by the browser. TURN service credentials use server-side HMAC-SHA1 separately from application encryption.

Keys contain exactly 32 printable ASCII characters. Generated keys encode 24 random bytes as 32 base64 characters, providing 192 bits of entropy. Chat plaintext is ASCII. Binary file slices become ASCII base64 inside an ASCII JSON envelope before encryption. Ciphertext, the 96-bit IV, and the full 128-bit authentication tag are displayed in hexadecimal. Every encrypted packet gets a fresh random IV.

The file size cap is **1 GiB**, or 1,073,741,824 bytes. Files use 12 KiB binary chunks, independent authenticated encryption, an ordered manifest, a bounded acknowledgment window, and backpressure. A receiver accepts the offer explicitly and downloads only after completion. The receiver keeps file parts in RAM, so browser memory and device capacity can make the usable limit smaller. A 1 GiB cap is not a claim that every device can complete a 1 GiB transfer. A transfer interrupted by disconnection must be sent again.

P2P chat history is retained only in participating browsers' RAM, bounded to 2,000 messages and an 8 MiB accounting budget. Actual browser heap use can differ. A returning peer can recover retained text history from a surviving peer after establishing the key again. Shared-secret reconnection uses the same secret; KDC reconnection may require a new handshake. Completed file bytes are not replayed as chat history. Leaving clears the application's session state. If every peer leaves or destroys its browser context, there is no server copy to recover. Downloads requested by the user remain on that user's device.

## Validation and explanation

```sh
npm test
npm run test:large
```

The current implementation passed 53 automated tests: 11 crypto integration, 9 protocol, 16 backend, 8 session, and 9 native DOM checks. Tests compare the fully manual AES-GCM, including GHASH, with independent Node AES-GCM, cover separate AAD/ciphertext padding and derived-key compatibility, and reject altered or malformed packets. The seven copied support modules and two MIT licenses are checked against the installed npm packages; removed cipher-library paths are unavailable.

The large-transfer verifier processes 64 MiB by default; use `npm run test:large -- --size-mib 1024` for its full 1 GiB local stream check. The current manual-GHASH version passed 67,108,864 bytes in 16.076 seconds, with matching source/output digests and bounded frames. This is a local cipher/protocol stream, not a browser or network transfer. Earlier 1 GiB and HTTP browser results are retained in the report with their original implementation scope; they were not rerun after manual GHASH was restored.

Read [the technical report](docs/REPORT.md), [the eight-minute demonstration and questions](docs/DEMO.md), and [security assumptions](docs/SECURITY.md).

For a statement-by-statement explanation of `src/shared/crypto.js`, read [the crypto walkthrough](docs/CRYPTO_WALKTHROUGH.md). It maps the manual key expansion, AES round operations, and GCM assembly to their textbook forms, including its manual GHASH arithmetic, then explains the inputs and outputs of the library hashing, key-derivation, and Base64 helpers.

## Project map

| Path | Responsibility |
| --- | --- |
| `index.html` | Readable dashboard HTML and native browser entry point |
| `src/app.js` | DOM event handlers, dashboard state, and session subscriptions |
| `src/ui/render.js` | Message, file, key-exchange, and encryption-inspector rendering |
| `src/styles.css` | Existing responsive dark dashboard and CSS animations |
| `public/icons.svg` | Locally stored official Lucide SVG paths |
| `src/shared/crypto.js` | Manual AES and complete GCM including GHASH; library SHA-256, PBKDF2/HMAC, and Base64; ASCII/Hex utilities |
| `src/client/crypto-worker.js` | Keeps expensive derivation and encryption off the interface thread |
| `src/client/session.js` | Session keys, KDC handshake, text, bounded recovery, and file protocol |
| `src/client/transport.js` | Room relay and automatic PeerJS/WebRTC connections |
| `src/client/protocol.js` | Limits, ASCII checks, replay window, and ordered file assembly |
| `server/index.js` | Memory-only presence, relay, KDC tickets, and TURN credentials |
| `scripts/vendor.mjs` | Copies pinned support-library modules and licenses into `vendor/` after installation |
| `scripts/build.mjs` | Optional static export by copying browser assets and support libraries |
| `compose.yaml` | HTTP application and optional self-hosted coturn |
| `docs/` | Report, security model, and demonstration script |

This is a readable educational implementation. Passing known-answer tests does not constitute a professional security audit, constant-time implementation, or production certification.
