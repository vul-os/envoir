// Hand-written type declaration for net/sync.js. This is a SIDECAR .d.ts, not a converted
// module: net/sync.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists only so client/test/net.test.ts gets real type-checking on the real-mode mailbox
// rebuild/merge logic. It describes sync.js's PUBLIC exports as implemented; it is not
// authoritative — if sync.js's behavior changes, this file must be updated by hand alongside it.

import type { Thread } from '../store.js';

/**
 * connect()'s actual requirement, narrower than the full NodeConfig: sync.js's own guard reads
 * only baseUrl/username/appPassword (`enabled`/`sendToken` are resolveNodeConfig()/sendMail()'s
 * concern, not connect()'s).
 */
export interface ConnectConfig {
  baseUrl: string;
  username: string;
  appPassword: string;
  sendToken?: string;
  enabled?: boolean;
}

export interface ConnectResult {
  ok: boolean;
  mode: 'real' | 'sim';
  count?: number;
  reason?: string;
}

export interface SyncResult {
  ok: boolean;
  changed?: boolean;
  count?: number;
  reason?: string;
}

/**
 * Merge server-rebuilt threads with locally-originated ones (drafts, just-sent, real-mode
 * replies) that the node has not (yet, or ever) served back. See sync.js's own header comment
 * for the exact supersession rule — this signature only captures the I/O shape.
 */
export function mergeLocalMail(serverThreads: Thread[]): Thread[];

/** Connect to the node with an explicit config, sync mail, and flip to REAL mode on success. */
export function connect(cfg: ConnectConfig): Promise<ConnectResult>;

/** Auto-connect on boot from the resolved node config; silent no-op if unconfigured/unreachable. */
export function autoConnect(): Promise<ConnectResult>;

/** Drop back to SIMULATION mode. */
export function disconnect(): void;

/** Refresh live mail while in REAL mode; no-op in SIMULATION mode. */
export function syncNow(): Promise<SyncResult>;
