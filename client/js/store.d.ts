// Hand-written type declaration for store.js. This is a SIDECAR .d.ts, not a converted module:
// store.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists so client/test/*.test.ts get real type-checking against the shared app state shape, and
// so other sidecars (net/send.d.ts, net/sync.d.ts) can import Thread/Msg/NodeConfig from one
// place. It describes store.js's PUBLIC exports and the state shape as implemented (cross-checked
// against seed.js and net/sync.js's message-mapping code); it is not authoritative — if store.js's
// shape changes, this file must be updated by hand alongside it.

export type NetMode = 'sim' | 'real';

/** Resolved node connection config (spec §8.1/§8.2/§13.5.1) — see resolveNodeConfig(). */
export interface NodeConfig {
  enabled: boolean;
  baseUrl: string;
  username: string;
  appPassword: string;
  sendToken: string;
}

/** An attachment reference as carried on a Msg (name/size only — no attachment upload here). */
export interface Attach {
  name: string;
  size: number;
}

/** One message within a mail Thread. */
export interface Msg {
  id: string;
  from: string;
  me?: boolean;
  to: string[];
  time: number;
  tier?: string;
  body: string;
  html?: boolean;
  text?: string;
  attach?: Attach[];
  /** Node-issued receipt (content) ids for a real-mode send — see net/send.js / net/sync.js. */
  nodeIds?: string[];
  /** Marks a thread/message that exists only in this client (see net/sync.js mergeLocalMail). */
  local?: boolean;
  provenance?: unknown;
  plusTag?: string;
}

/** A mail conversation thread (folder ∈ inbox | sent | drafts | archive | spam | trash). */
export interface Thread {
  id: string;
  subject: string;
  labels: string[];
  folder: string;
  read: boolean;
  starred: boolean;
  snoozeUntil: number | null;
  tier: string;
  verified: boolean;
  legacy: boolean;
  msgs: Msg[];
  local?: boolean;
  calendarEventId?: string;
  scheduledAt?: number | null;
}

export interface Group {
  id: string;
  name: string;
  address: string;
  handle?: string;
  mode?: string;
  joinPolicy?: string;
  membershipVisible?: boolean;
  created?: number;
  members?: Array<{ address: string; role: string; hidden?: boolean }>;
}

export interface NetState {
  mode: NetMode;
  status: string;
  error: string | null;
  client: unknown;
  accountId: string | null;
  sessionState: string | null;
  lastSync: number;
}

export interface UiState {
  mailFolder: string;
  mailLabel: string | null;
  selThread: string | null;
  selChat: string | null;
  selGroup: string | null;
  chatThread: unknown;
  calView: string;
  calCursor: number;
  selEvent: unknown;
  selected: Set<string>;
  search: string;
  mobileDetail: boolean;
  compose: unknown;
}

export interface FilterRule {
  id: string;
  from: string;
  subject: string;
  label: string;
  action: string;
  enabled: boolean;
}

export interface Settings {
  theme: string;
  mailDensity: string;
  tierDefault: string;
  gateway: boolean;
  presence: boolean;
  signatures: unknown[];
  filters: FilterRule[];
  vacation: { enabled: boolean; subject: string; message: string; from: string; to: string };
  blocked: string[];
  allowed: string[];
  node: NodeConfig;
}

export interface State {
  view: string;
  mail: Thread[];
  chats: unknown[];
  events: unknown[];
  files: unknown[];
  groups: Group[];
  devices: unknown[];
  sessions: unknown[];
  labels: unknown[];
  people: unknown[];
  ui: UiState;
  settings: Settings;
  net: NetState;
}

export const state: State;

export function setNetStatus(patch: Partial<NetState>): NetState;

/** Resolves the injected-host (Tauri) config if present, else the saved Settings → Node config. */
export function resolveNodeConfig(): NodeConfig;

export function initStore(): void;

export function simulateIncomingInvite(): {
  event: { id: string; [k: string]: unknown };
  thread: Thread;
  organizer: { address: string; [k: string]: unknown };
};

export function saveSettings(): void;
export function loadSettings(): void;

export function threadsIn(folder: string, label?: string | null): Thread[];
export function lastTime(t: Thread): number;
export function thread(id: string): Thread | undefined;
export function unreadCount(folder: string): number;

export function uid(prefix?: string): string;

export const SEARCH_OPERATORS: string[];

export interface ParsedSearch {
  text: string;
  from: string | null;
  to: string | null;
  subject: string | null;
  label: string | null;
  in: string | null;
  flags: Record<string, boolean>;
}
export function parseSearch(raw: string): ParsedSearch;
export function searchIsGlobal(p: ParsedSearch): boolean;
export function matchThread(t: Thread, p: ParsedSearch | null): boolean;
export function stripHtml(s: unknown): string;

export function ruleMatches(rule: FilterRule, t: Thread): boolean;
export function applyFilters(threads?: Thread[]): number;

export const normAddr: (a: string) => string;
export function isBlocked(addr: string): boolean;
export function isAllowed(addr: string): boolean;
export function blockSender(addr: string): void;
export function unblockSender(addr: string): void;
export function allowSender(addr: string): void;
export function threadSender(t: Thread): string;
