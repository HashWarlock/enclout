# Secure Connector: a complete engineering design plan

## Canonical Status and Phase Mapping

This document is a **vision/engineering reference**, not the implementation authority.
Canonical implementation authority is:

- `docs/superpowers/specs/2026-04-08-enclout-canonical-architecture-design.md`
- `docs/superpowers/plans/2026-04-08-enclout-drift-closure-implementation-plan.md`

Phase tags for this document:

- **Phase A (Trust Plane):** request/session APIs, local approval, attestation verification, signed bundle delivery.
- **Phase B (Transport Plane):** CVM-side connector runtime, SSH reverse connectivity, shell/port-forward data plane.
- **Phase C (Forensics Plane):** full terminal/file-op capture, endpoint-local encryption, tamper-evident audit chain.

Most sections below are **Phase B/C design** material and are not claims of current repository implementation status.

---

**The Secure Connector system establishes TEE-attested, SSH-tunneled browser control channels between a Confidential VM running dstack and a user's local machine.** The architecture derives deterministic ed25519 keys inside Intel TDX hardware, binds those keys to attestation quotes, tunnels Chrome DevTools Protocol traffic over SSH, and verifies the entire chain client-side before trusting the connection. This document provides production-ready TypeScript code, exact API contracts, infrastructure configuration, and cross-platform agent design for forward implementation phases.

The design draws on architectural patterns from ngrok (stream multiplexing), Cloudflare Tunnel (outbound-only HA connections), Tailscale (tiered key hierarchy), and Teleport (certificate-authority-based identity) while adding hardware attestation as the root of trust. Every secret originates inside the TEE's KMS, never touches disk in plaintext outside the enclave, and can be cryptographically verified by the client before any tunnel is established.

---

## 1. TEE-side key derivation with DstackClient

The `@phala/dstack-sdk` package (v0.5.7, Apache-2.0) provides the `DstackClient` class — the sole interface between application code and the dstack Guest Agent running inside the Confidential VM. The SDK communicates over a Unix domain socket at **`/var/run/dstack.sock`** via HTTP, which must be volume-mounted into the Docker container.

### Constructor and transport

```typescript
import { DstackClient } from '@phala/dstack-sdk';

// Production: auto-connects to /var/run/dstack.sock
const client = new DstackClient();

// Local development: connect to simulator
const devClient = new DstackClient(process.env.DSTACK_SIMULATOR_ENDPOINT);
// Simulator typically runs at http://localhost:8090
```

The constructor accepts an optional `endpoint?: string`. When omitted, it connects to `/var/run/dstack.sock` (dstack OS 0.5.x) with fallback to `/var/run/tappd.sock` (0.3.x, deprecated). When a string URL is provided, it uses HTTP transport — used exclusively with the local simulator (`phala simulator start` or the `phalanetwork/tappd-simulator:latest` Docker image).

### Core API surface — exact method signatures

**`client.info(): Promise<InfoResponse>`** returns TEE instance metadata:

```typescript
interface InfoResponse {
  app_id: string;       // Hex application identity from KMS
  instance_id: string;  // Specific CVM instance identifier
  app_name: string;     // Name from app-compose.json
  tcb_info: string;     // JSON-encoded Trusted Computing Base info
}
```

**`client.getKey(path: string, subject?: string): Promise<GetKeyResponse>`** derives a **deterministic secp256k1 key** from the KMS. The same `path` always yields the same key for the same `app_id` — different apps get different keys even with identical paths. This is the foundation for SSH key generation:

```typescript
interface GetKeyResponse {
  key: Uint8Array;                // 32-byte private key material
  signature_chain: string[];      // KMS authenticity proof chain
  asUint8Array(): Uint8Array;     // Legacy helper
}

const keyResult = await client.getKey('ssh/connector', 'ed25519-seed');
// keyResult.key is the deterministic 32-byte seed
```

**`client.getQuote(data: string | Uint8Array): Promise<GetQuoteResponse>`** generates a TDX remote attestation quote. The actual `REPORT_DATA` written to the TDX driver is **`sha2_256(data)`**, padded to 64 bytes:

```typescript
interface GetQuoteResponse {
  quote: string;       // Hex-encoded TDX attestation quote
  event_log: string;   // JSON array of event log entries
}

const quote = await client.getQuote(publicKeyBytes);
```

**`client.getTlsKey(options: TlsKeyOptions): Promise<TlsKeyResponse>`** generates **fresh random** TLS certificates on every call (not deterministic — designed for TLS/SSL, not identity):

```typescript
interface TlsKeyOptions {
  subject?: string;          // Certificate CN
  altNames?: string[];       // SANs (domains/IPs)
  usageRaTls?: boolean;      // Embed TDX quote in cert extension
  usageServerAuth?: boolean; // Default: true
  usageClientAuth?: boolean; // Default: false
}

interface TlsKeyResponse {
  key: string;                // Private key (PEM)
  certificate_chain: string;  // Certificate chain (PEM)
}
```

**`client.emitEvent(label: string, data: string): Promise<void>`** (dstack OS 0.5.0+) emits custom events that are automatically included in subsequent attestation quotes via the event log, enabling auditable application-level event chains.

### encryptEnvVars utility

The SDK exports `encryptEnvVars` for injecting secrets into CVMs without exposing them to the deployment pipeline:

```typescript
import { encryptEnvVars, verifyEnvEncryptPublicKey, type EnvVar } from '@phala/dstack-sdk';

const envVars: EnvVar[] = [
  { key: 'DATABASE_URL', value: 'postgresql://user:pass@host:5432/db' },
  { key: 'API_SECRET', value: 'sk-...' },
];

// Verify KMS public key authenticity (prevents MITM)
const kmsIdentity = verifyEnvEncryptPublicKey(publicKeyBytes, signatureBytes, appId);
// Returns: compressed secp256k1 pubkey of KMS if valid, null if invalid

// Encrypt with X25519 ECDH → AES-256-GCM
const encrypted: string = await encryptEnvVars(envVars, publicKeyHex);
// Output: hex(ephemeral_pubkey + iv + ciphertext)
```

Inside the CVM, the Guest Agent decrypts via the KMS X25519 shared secret and writes env vars to `/dstack/.hostshared/.decrypted-env`.

### app-compose.json and Docker integration

The application manifest defines the deployment configuration. Its hash is extended into **RTMR3** as the `compose-hash` event, making the entire application configuration verifiable via attestation:

```json
{
  "manifest_version": 1,
  "name": "secure-connector",
  "runner": "docker-compose",
  "docker_compose_file": "services:\n  connector:\n    image: ghcr.io/org/connector:latest\n    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n    environment:\n      - NODE_ENV=production\n      - SSH_PORT=2222",
  "allowed_envs": ["SSH_PORT", "BROWSER_PROFILE_PATH"],
  "kms_enabled": true,
  "public_tcbinfo": true,
  "gateway_enabled": false
}
```

The `docker_compose_file` field is the YAML content as a string (not a file path). The socket volume mount is mandatory for SDK access.

---

## 2. Deterministic ed25519 keypair from TEE seed material

The 32-byte seed from `getKey()` must be transformed into a valid ed25519 SSH keypair. Three libraries handle this; **`@noble/ed25519`** is the recommended choice — audited by Cure53, zero dependencies, **5KB gzipped**, ~7600 ops/sec for key generation versus ~920 for tweetnacl.

### Complete key derivation pipeline

```typescript
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { createPrivateKey, type KeyObject } from 'node:crypto';

// Enable synchronous operations
ed.hashes.sha512 = sha512;

// Ed25519 PKCS8 DER prefix: 16 bytes wrapping a 32-byte seed into 48-byte PKCS8
const ED25519_PKCS8_PREFIX = Buffer.from(
  '302e020100300506032b657004220420', 'hex'
);

/**
 * SSH wire-format string: [4-byte big-endian length][data]
 */
function encodeSSHString(data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  return Buffer.concat([len, data]);
}

/**
 * Derive a full ed25519 identity from a 32-byte TEE seed.
 * Returns everything needed for SSH: public key in authorized_keys format,
 * private key as PEM for ssh2, and Node.js KeyObject for crypto operations.
 */
export function deriveEd25519Identity(seed: Uint8Array): {
  publicKey: Uint8Array;
  sshPublicKey: string;
  privateKeyPem: string;
  privateKeyObject: KeyObject;
} {
  if (seed.length !== 32) throw new Error('Ed25519 seed must be exactly 32 bytes');

  // 1. Derive 32-byte public key from seed
  const publicKey = ed.getPublicKey(seed);  // sync, requires sha512 set above

  // 2. Format as OpenSSH authorized_keys line (RFC 8709)
  // Blob: [uint32(11)]["ssh-ed25519"][uint32(32)][32-byte-pubkey] = 51 bytes
  const keyType = Buffer.from('ssh-ed25519');
  const blob = Buffer.concat([
    encodeSSHString(keyType),
    encodeSSHString(Buffer.from(publicKey)),
  ]);
  const sshPublicKey = `ssh-ed25519 ${blob.toString('base64')} connector@tee`;

  // 3. Wrap seed in PKCS8 DER for Node.js crypto
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privateKeyObject = createPrivateKey({
    key: pkcs8Der, format: 'der', type: 'pkcs8'
  });

  // 4. Export as PEM for ssh2 library consumption
  const privateKeyPem = privateKeyObject.export({
    type: 'pkcs8', format: 'pem'
  }) as string;

  return { publicKey, sshPublicKey, privateKeyPem, privateKeyObject };
}
```

The PKCS8 DER structure for ed25519 is exactly **48 bytes**: a 16-byte ASN.1 prefix (`SEQUENCE > INTEGER(0) > SEQUENCE(OID 1.3.101.112) > OCTET STRING > OCTET STRING`) followed by the 32-byte seed. This is the only reliable way to import a raw ed25519 seed into Node.js `crypto.createPrivateKey()`.

### Library comparison for reference

| Library | Private key format | Public key | Speed | Size |
|---|---|---|---|---|
| `@noble/ed25519` | 32-byte seed | 32-byte `Uint8Array` | ~7,600 ops/sec | 5KB |
| `tweetnacl` | 64-byte (seed ∥ pubkey) | 32-byte `Uint8Array` | ~920 ops/sec | 25KB |
| Node.js `crypto` | PKCS8 DER (48 bytes) | SPKI DER | Native speed | Built-in |

The critical difference: tweetnacl's `nacl.sign.keyPair.fromSeed(seed)` returns a **64-byte** `secretKey` (seed concatenated with pubkey), while noble returns just the 32-byte seed. For ssh2 consumption, the PKCS8 PEM export from Node.js crypto is the most reliable path.

---

## 3. SSH tunnel infrastructure with ssh2

The `ssh2` package (pure JavaScript, Node.js v10.16+, ed25519 support on Node v12+) is the primary SSH implementation. The connector uses it to establish an authenticated tunnel from the TEE to the user's machine, then forward CDP traffic through it.

### Interface contract for the SSH tunnel manager

```typescript
import { Client, ConnectConfig, ClientChannel } from 'ssh2';
import * as net from 'node:net';

interface TunnelConfig {
  host: string;
  port: number;
  username: string;
  privateKeyPem: string;      // PEM string from deriveEd25519Identity()
  localCdpPort: number;       // Remote Chrome's debugging port (9222)
  tunnelLocalPort: number;    // Local port to bind the tunnel on
  keepaliveIntervalMs: number;
  maxRetries: number;
}

/**
 * Manages an SSH connection with automatic reconnection and
 * local port forwarding for CDP tunnel.
 */
export class SecureTunnel {
  private conn: Client | null = null;
  private tunnelServer: net.Server | null = null;
  private retryCount = 0;
  private destroyed = false;

  constructor(private config: TunnelConfig) {}

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const conn = new Client();

      const sshConfig: ConnectConfig = {
        host: this.config.host,
        port: this.config.port,
        username: this.config.username,
        privateKey: this.config.privateKeyPem,  // PEM string, NOT file path
        keepaliveInterval: this.config.keepaliveIntervalMs,
        keepaliveCountMax: 3,
        readyTimeout: 20_000,
        algorithms: {
          serverHostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256'],
        },
      };

      conn
        .on('ready', () => {
          this.conn = conn;
          this.retryCount = 0;
          resolve();
        })
        .on('error', (err: Error) => {
          if (this.destroyed) return;
          if (this.retryCount < this.config.maxRetries) {
            const delay = 3000 * Math.pow(2, this.retryCount++);
            setTimeout(() => this.connect().then(resolve).catch(reject), delay);
          } else {
            reject(new Error(`SSH failed after ${this.config.maxRetries} retries: ${err.message}`));
          }
        })
        .on('close', () => {
          this.conn = null;
          if (!this.destroyed) {
            setTimeout(() => this.connect().catch(console.error), 3000);
          }
        })
        .connect(sshConfig);
    });
  }

  /**
   * Create local TCP server that forwards connections through SSH
   * to the remote Chrome debugging port. Equivalent to:
   *   ssh -L tunnelLocalPort:127.0.0.1:localCdpPort
   */
  async startCdpTunnel(): Promise<net.Server> {
    if (!this.conn) throw new Error('SSH not connected');

    return new Promise((resolve, reject) => {
      const server = net.createServer((socket: net.Socket) => {
        this.conn!.forwardOut(
          socket.remoteAddress ?? '127.0.0.1',
          socket.remotePort ?? 0,
          '127.0.0.1',                    // Chrome binds to localhost on remote
          this.config.localCdpPort,       // Remote debugging port (9222)
          (err: Error | undefined, stream: ClientChannel) => {
            if (err) { socket.end(); return; }
            stream.pipe(socket).pipe(stream);
            stream.on('close', () => socket.destroy());
            socket.on('close', () => stream.destroy());
            socket.on('error', () => stream.destroy());
            stream.on('error', () => socket.destroy());
          },
        );
      });

      server.on('error', reject);
      server.listen(this.config.tunnelLocalPort, '127.0.0.1', () => {
        this.tunnelServer = server;
        resolve(server);
      });
    });
  }

  async destroy(): Promise<void> {
    this.destroyed = true;
    this.tunnelServer?.close();
    this.conn?.end();
    this.conn = null;
  }
}
```

The `forwardOut(srcIP, srcPort, dstIP, dstPort, callback)` method creates a `direct-tcpip` channel — functionally identical to `ssh -L`. Each incoming TCP connection on the local server triggers a new SSH channel piped bidirectionally to the remote destination. The `srcIP`/`srcPort` parameters are informational (logged on the SSH server); the `dstIP`/`dstPort` specify where the remote side connects.

---

## 4. Chrome DevTools Protocol over the tunnel

Chrome's remote debugging interface is a **zero-authentication WebSocket API** that grants complete browser control — cookie extraction, JavaScript execution, file system reads, input capture, screenshot capture. **Exposing CDP on any network interface is a critical security vulnerability.** The SSH tunnel ensures CDP traffic never leaves localhost on either end.

### Chrome launch configuration on the remote CVM

```bash
google-chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/opt/browser-profiles/session-${SESSION_ID} \
  --no-first-run \
  --no-default-browser-check \
  --disable-default-apps \
  --disable-popup-blocking \
  --disable-background-timer-throttling \
  --disable-renderer-backgrounding \
  --disable-device-discovery-notifications \
  --remote-allow-origins=* \
  --restore-last-session
```

Two flags are critically important. **`--remote-debugging-port=9222`** enables the CDP WebSocket server, bound to `127.0.0.1` by default (never set `--remote-debugging-address=0.0.0.0`). **`--user-data-dir`** is mandatory from Chrome 136+ — without a custom data directory, debugging flags are silently ignored on standard Chrome. The `--user-data-dir` path stores cookies, localStorage, IndexedDB, service workers, history, extensions, and saved passwords. Reusing the same directory across launches preserves the complete session state.

For headed (user-visible) sessions, simply omit `--headless`. The `--restore-last-session` flag re-opens previously active tabs on relaunch.

### Playwright CDP connection through the tunnel

```typescript
import { chromium, Browser, BrowserContext, Page } from 'playwright';

interface CdpConnectionOptions {
  tunnelPort: number;      // Local end of SSH tunnel
  timeout?: number;        // Connection timeout (default 30s)
  maxRetries?: number;
}

async function connectBrowser(opts: CdpConnectionOptions): Promise<Browser> {
  const url = `http://localhost:${opts.tunnelPort}`;
  const maxRetries = opts.maxRetries ?? 5;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const browser = await chromium.connectOverCDP(url, {
        timeout: opts.timeout ?? 30_000,
      });
      return browser;
    } catch {
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
  }
  throw new Error(`CDP connection failed after ${maxRetries} attempts`);
}

// Usage after tunnel is established
const browser = await connectBrowser({ tunnelPort: 9222 });

// Access the default context — contains all existing user tabs
const defaultContext: BrowserContext = browser.contexts()[0];
const pages: Page[] = defaultContext.pages();

// Enumerate existing tabs
for (const page of pages) {
  console.log(`Tab: ${page.url()} — "${await page.title()}"`);
}

// Create new tab in user's context (shares cookies/session)
const newPage = await defaultContext.newPage();
await newPage.goto('https://example.com');

// Create isolated context (separate cookie jar)
const isolated = await browser.newContext();
const sandboxedPage = await isolated.newPage();
```

The `connectOverCDP()` method accepts either an HTTP URL (which fetches `/json/version` to discover the WebSocket URL) or a direct WebSocket URL. Playwright notes this is "significantly lower fidelity" than their native protocol — it works for browser control but lacks some advanced features. The connection has **no auto-reconnection**; listen for `browser.on('disconnected', ...)` and implement retry logic.

Chrome also exposes HTTP endpoints on the debugging port: **`GET /json/list`** returns all open targets with their WebSocket URLs, **`PUT /json/new?url`** creates a new tab, and **`GET /json/close/{targetId}`** closes a specific target.

---

## 5. Client-side connector agent design

The agent runs on the user's local machine, manages SSH authorized keys, verifies TDX attestation, and establishes the tunnel. After evaluating four frameworks, **Go** is the recommended language for the agent binary, with **Rust** as an alternative for security-critical components.

### Why Go wins for this use case

Go produces **8–15MB static binaries** with zero dependencies, offers trivial cross-compilation (`GOOS=linux GOARCH=amd64 go build`), includes excellent SSH libraries (`golang.org/x/crypto/ssh`), and has a mature system tray ecosystem (`fyne.io/systray`). Rust offers better memory safety guarantees and ~30% performance advantage, but the SSH key management and tray menu workload doesn't demand it. Electron is rejected outright — **100–200MB binary and 100–300MB idle memory** is unacceptable for a background agent.

### SSH authorized_keys management

The agent must install the TEE-derived public key without disturbing the user's existing SSH configuration. Two approaches:

**Approach A — Separate AuthorizedKeysFile (recommended):**

```sshd_config
# /etc/ssh/sshd_config — append, do not replace
AuthorizedKeysFile .ssh/authorized_keys /var/lib/connector-agent/keys/%u/authorized_keys
```

The agent writes its managed keys to `/var/lib/connector-agent/keys/<username>/authorized_keys`, owned by `root:root` with `0644` permissions. The user's own `~/.ssh/authorized_keys` remains untouched. Updates use atomic `rename()` to prevent partial reads.

**Approach B — AuthorizedKeysCommand (dynamic, preferred for fleet management):**

```sshd_config
AuthorizedKeysCommand /opt/connector-agent/bin/fetch-keys %u
AuthorizedKeysCommandUser connector-agent-keyuser
```

The script must be owned by root, not group/world-writable, and outputs `authorized_keys` lines to stdout. The `AuthorizedKeysCommandUser` must be a dedicated unprivileged account.

### OS sandboxing configuration

On **Linux**, the agent applies `seccomp-bpf` filters (allowlisting only `read`, `write`, `socket`, `connect`, `exit_group`, and a minimal set of additional syscalls) plus network namespace isolation via `unshare --net --user`. The **Landlock** LSM (kernel ≥5.13) adds filesystem-level ACLs restricting the agent to its key directory and socket paths.

On **macOS**, the entitlements plist requires `com.apple.security.app-sandbox` (true), `com.apple.security.network.client` (true for outbound SSH), and `keychain-access-groups` for secure key storage. Set `LSUIElement=1` in `Info.plist` to hide the Dock icon while showing only the system tray.

On **Windows**, the agent runs as a service under `NT SERVICE\ConnectorAgent` with a restricted token at **Low integrity level** (`icacls agent.exe /setintegritylevel Low`). For stronger isolation, use an **AppContainer** with `SECURITY_CAPABILITY_INTERNET_CLIENT` for network access.

### Installer toolchains by platform

- **macOS**: `pkgbuild` → `productbuild` for `.pkg`; `hdiutil create` for `.dmg`; Tauri generates both automatically
- **Windows**: WiX Toolset v4+ for `.msi`; NSIS or Inno Setup for `.exe` installers
- **Linux**: `dpkg-deb` for `.deb`, `rpmbuild` for `.rpm`, `appimagetool` for AppImage; **GoReleaser** automates all three plus tar.gz in one config file

---

## 6. TDX attestation verification on the client

Before the agent trusts a TEE-derived SSH key, it must verify the TDX attestation quote — confirming the key was generated inside genuine Intel TDX hardware running the expected software. This is the cryptographic link between "this public key" and "this exact code running in this exact TEE."

### TDX quote structure

A TDX quote (DCAP v4/v5) consists of a **48-byte header**, a **584-byte TD Report body** (TDReport10), and variable-length authentication data containing an ECDSA signature, attestation key, and PCK certificate chain.

The TD Report body contains the measurements that matter:

| Field | Size | Meaning |
|---|---|---|
| **MRTD** | 48 bytes | SHA-384 of initial TD memory — build-time measurement of the VM image |
| **RTMR[0]** | 48 bytes | Virtual firmware/hardware measurement |
| **RTMR[1]** | 48 bytes | OS boot measurement |
| **RTMR[2]** | 48 bytes | OS runtime measurement |
| **RTMR[3]** | 48 bytes | Application-specific — in dstack: `compose-hash`, `app-id`, `instance-id`, `key-provider` |
| **REPORT_DATA** | 64 bytes | User-supplied data — **this is where the public key hash goes** |

For public key binding, the TEE sets `REPORT_DATA = SHA-256(ed25519_public_key) || zeros(32)`. The client verifies that the `REPORT_DATA` in the quote matches the SHA-256 of the SSH public key it received, proving the key was generated inside the attested TEE.

### Verification chain — 12 steps

The full verification pipeline follows the Intel DCAP specification:

1. Parse the quote — extract header, TD Report body, and authentication data
2. Extract the ECDSA-P256 signature and Attestation Key (AK) from auth data
3. **Verify the quote signature** using the AK public key
4. Extract the PCK Certificate from certification data
5. Verify the AK was certified by the PCK (AK cert signed by PCK private key)
6. Build the certificate chain: **PCK Cert → Intel Platform CA → Intel SGX Root CA**
7. Validate each certificate (signatures, validity periods, X.509 extensions)
8. Check Certificate Revocation Lists from Intel PCS (`api.trustedservices.intel.com`)
9. Fetch TCB Info using the FMSPC from the PCK cert's extensions
10. Verify TCB Security Version Numbers meet the required level
11. Fetch QE Identity and verify QE measurements (MRSIGNER, ISVPRODID, ISVSVN)
12. **Verify MRTD, RTMRs, and REPORT_DATA match expected values**

### Client-side verification implementation

The **`@lit-protocol/dcap-qvl-ts`** package provides a pure JavaScript/TypeScript port of Phala's Rust `dcap-qvl` library. It handles quote parsing, ECDSA signature verification, certificate chain validation, and TCB level checking — running entirely in Node.js or browsers without native dependencies:

```typescript
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';

const verifier = new DcapVerifier({
  pccsUrl: 'https://pccs.example.com/sgx/certification/v4',
  timeout: 10_000,
  cacheResults: true,
});

// quoteHex comes from the TEE's client.getQuote() response
const quoteBytes = Buffer.from(quoteHex, 'hex');
const result = await verifier.verifyQuote(quoteBytes);

// Verify public key binding
const expectedReportData = Buffer.alloc(64);
crypto.createHash('sha256').update(receivedPublicKey).digest()
  .copy(expectedReportData, 0);

if (!result.reportData.equals(expectedReportData)) {
  throw new Error('Public key not bound to attestation quote');
}
```

For more comprehensive verification including OS image and source code checks, the **`@phala/dstack-verifier`** package (from the trust-center monorepo) performs hardware verification via `dcap-qvl`, OS measurement comparison against known dstack images, compose-hash extraction from RTMR3 event logs, and optional domain/TLS verification. Phala also operates a public verification endpoint at **proof.t16z.com** for interactive quote inspection.

After the February 2026 security audit, `dcap-qvl` v0.3.9+ enforces mandatory QE Identity verification and stricter TCB status checking by default — these hardened defaults should be used in production.

---

## 7. Architectural lessons from existing tunnel solutions

Four production tunnel systems inform the Secure Connector's design decisions:

**ngrok** uses a custom stream-multiplexing protocol called **muxado** (influenced by HTTP/2 framing) over TLS on port 443. The agent authenticates with a bearer token (authtoken) scoped via ACLs. Key lesson: **agent SDKs** (Go, Python, Rust, JS) that embed tunnel capability directly into application code eliminate sidecar management entirely.

**Cloudflare Tunnel** runs the `cloudflared` Go binary, which maintains **4 concurrent QUIC connections** to different Cloudflare edge colos for redundancy, with automatic HTTP/2 fallback if UDP is blocked. Authentication uses either a `cert.pem` (account-level) plus `<UUID>.json` (tunnel-level) or a single dashboard-issued token. Post-quantum key exchange (ML-KEM) is enabled by default for QUIC. Key lesson: **multiple HA connections with independent backoff strategies** ensure resilience.

**Tailscale** builds a WireGuard-based peer-to-peer mesh where the control plane only coordinates key exchange — **data flows directly between peers, never through a central proxy**. Its three-tier key hierarchy (machine key → node key → WireGuard session keys rotating every 2 minutes) and **Tailnet Lock** (cryptographic node key signing to prevent coordination server compromise) represent the gold standard for key management. All authentication is delegated to external identity providers.

**Teleport** eliminates static SSH keys entirely by operating a **Certificate Authority that issues short-lived SSH and X.509 certificates** (default TTL: 12 hours). Agents connect via reverse SSH tunnels to the Proxy Service. Every connection is authenticated twice (at proxy and at node), with full session recording for compliance. Key lesson: **short-lived certificates eliminate the revocation problem** — expired credentials are automatically invalid.

### Design decisions for the Secure Connector

| Decision | Choice | Rationale |
|---|---|---|
| Agent-to-TEE transport | SSH (ed25519) over TCP | Proven, universally firewall-friendly, works with ssh2 library |
| Key lifecycle | TEE-deterministic, rotate via path versioning | No static secrets on disk; new `getKey('ssh/v2', ...)` path creates new identity |
| Trust anchor | TDX attestation quote with pubkey binding | Hardware root of trust; client verifies before establishing tunnel |
| Connection redundancy | Single SSH connection with keepalive + reconnect | Sufficient for single-user CDP tunnel; Cloudflare's 4-connection model is for multi-tenant edge |
| Agent distribution | Single Go binary via platform package managers | Follows ngrok/cloudflared pattern; GoReleaser for all platforms |
| Authentication model | Attestation-first: verify quote → trust pubkey → establish SSH | Combines Teleport's certificate approach with hardware attestation |

---

## 8. End-to-end connection flow

The full system operates as a three-phase handshake with hardware verification at its core:

**Phase 1 — TEE bootstraps identity.** On CVM startup, the connector service calls `client.getKey('ssh/connector/v1', 'ed25519')` to derive a deterministic 32-byte seed, generates the ed25519 keypair via `@noble/ed25519`, formats the public key as `ssh-ed25519`, then calls `client.getQuote(sha256(publicKey))` to produce a TDX attestation quote binding the key to the hardware. The public key and quote are published to the control plane (API endpoint or on-chain).

**Phase 2 — Client verifies and trusts.** The agent fetches the public key and quote, runs `dcap-qvl-ts` verification (full certificate chain → Intel root CA, TCB level check, QE identity verification), confirms `REPORT_DATA == sha256(publicKey)`, checks MRTD and RTMR values against known-good measurements, and only then writes the public key to the managed `authorized_keys` file.

**Phase 3 — Tunnel establishment.** The TEE-side connector initiates an outbound SSH connection to the user's machine using the derived ed25519 private key. The ssh2 `forwardOut` creates a `direct-tcpip` channel forwarding `127.0.0.1:9222` (Chrome's debugging port) to a local port on the user's machine. Playwright's `connectOverCDP()` then attaches to this tunneled port, gaining full browser control over an encrypted, attestation-verified channel.

The entire key chain is deterministic: the same CVM image + app-compose.json always produces the same `app_id`, which always derives the same seed from the KMS, which always generates the same ed25519 keypair. Any change to the code, configuration, or TEE environment produces a different key — and a different attestation quote — which the client will detect and reject.

---

## Conclusion

The Secure Connector architecture achieves something none of the existing tunnel solutions offer: **a hardware-attested root of trust for the tunnel endpoint itself**. While ngrok and Cloudflare trust their edge infrastructure, and Tailscale and Teleport trust their coordination servers, the Secure Connector's trust derives from Intel TDX silicon — verifiable by any client with the attestation quote and Intel's public root CA.

Three implementation priorities emerge from this design. First, the TEE-side service is straightforward TypeScript: `DstackClient` → `getKey()` → `@noble/ed25519` → `ssh2` tunnel — all using well-maintained, audited libraries with clear APIs. Second, the client agent should be a Go binary using `fyne.io/systray` and `golang.org/x/crypto/ssh`, with `dcap-qvl-ts` compiled to WASM or called via a Rust FFI bridge for quote verification. Third, the security-critical path is the attestation verification — the `dcap-qvl` v0.3.9+ hardened defaults (mandatory QE Identity verification, strict TCB enforcement) must be used without relaxation.

The most novel architectural insight is that **deterministic key derivation from the KMS eliminates key distribution entirely**. The TEE doesn't need to send its private key anywhere or store it persistently — it re-derives the same key on every boot from the same `getKey()` path. The client only needs the public key and the attestation proof that the key was generated inside genuine hardware. This is fundamentally different from certificate-based systems like Teleport, where a CA must actively issue and distribute credentials. Here, the hardware *is* the CA.
