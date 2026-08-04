// Hand-written type declaration for net/jmap.js. This is a SIDECAR .d.ts, not a converted
// module: net/jmap.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This
// file exists only so client/test/net.test.ts gets real type-checking on the RFC 8620/8621
// wire surface. It describes jmap.js's PUBLIC exports as implemented; it is not authoritative —
// if jmap.js's behavior changes, this file must be updated by hand alongside it.

export const DEFAULT_BASE_URL: string;
export const CAP_CORE: string;
export const CAP_MAIL: string;
export const CAP_SUBMISSION: string;

/** A raw JMAP method call/response triple: [name, args, callId] (RFC 8620 §3.3). */
export type JmapMethodCall = [string, Record<string, unknown>, string];
export type JmapInvocation = [string, Record<string, unknown> | undefined, string];

export interface JmapErrorOptions {
  status?: number;
  body?: unknown;
}

/** A JMAP transport error carrying the HTTP status and any parsed problem body. */
export class JmapError extends Error {
  status: number;
  body: unknown;
  constructor(message: string, opts?: JmapErrorOptions);
}

export interface JmapClientConfig {
  baseUrl?: string;
  username?: string;
  appPassword?: string;
  timeoutMs?: number;
}

/** The RFC 8620 §2 Session resource, as the node serves it. */
export interface JmapSession {
  capabilities: Record<string, unknown>;
  accounts: Record<string, unknown>;
  primaryAccounts: Record<string, string>;
  username: string;
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl: string;
  state: string;
}

/** The RFC 8620 §5.2 Email/changes delta shape. */
export interface JmapChangesDelta {
  accountId: string;
  oldState: string;
  newState: string;
  hasMoreChanges: boolean;
  created: string[];
  updated: string[];
  destroyed: string[];
}

/** A parsed JMAP Response with helpers to pull a method call's result by its callId. */
export class JmapResponse {
  methodResponses: JmapInvocation[];
  sessionState: string | null;
  createdIds: unknown;
  constructor(body: { methodResponses?: JmapInvocation[]; sessionState?: string | null; createdIds?: unknown });
  /** The full [name, args, callId] invocation for a callId (the FIRST match), or null. */
  invocation(callId: string): JmapInvocation | null;
  /** Throws JmapError if the call came back as a method-level `error` invocation. */
  arguments(callId: string): Record<string, unknown> | null;
}

/** A live JMAP client bound to one node account (RFC 8620 Core + RFC 8621 Mail). */
export class JmapClient {
  baseUrl: string;
  username: string;
  appPassword: string;
  timeoutMs: number;
  session: JmapSession | null;
  accountId: string;
  apiUrl: string;
  downloadUrl: string;
  readonly authHeader: string;
  readonly sessionState: string | null;

  constructor(cfg?: JmapClientConfig);

  /** GET /jmap/session. Discovers accountId, `state`, and the api/download URLs. */
  discover(): Promise<JmapSession>;
  /** A cheap reachability + auth probe: resolves true iff the node answers session with 200. */
  ping(): Promise<boolean>;
  /** POST /jmap/api/: send a batch of method calls, get back a parsed JmapResponse. */
  request(
    methodCalls: JmapMethodCall[],
    opts?: { using?: string[]; createdIds?: Record<string, string> },
  ): Promise<JmapResponse>;
  mailboxGet(ids?: string[] | null): Promise<{ list: Array<{ id: string; role?: string; name?: string }> } | null>;
  emailQuery(filter?: unknown, extra?: Record<string, unknown>): Promise<{ ids: string[] } | null>;
  emailGet(ids?: string[] | null, properties?: string[] | null): Promise<{ list: unknown[]; notFound: string[] } | null>;
  /** Email/query + Email/get chained via a back-reference (RFC 8620 §3.7) in one round-trip. */
  emailQueryGet(
    filter?: unknown,
    properties?: string[] | null,
  ): Promise<{ list: unknown[]; notFound?: string[] } | null>;
  threadGet(ids: string[]): Promise<unknown>;
  /** Email/changes since `sinceState`, or `{ cannotCalculateChanges: true }` on an unusable token. */
  emailChanges(sinceState: string): Promise<JmapChangesDelta | { cannotCalculateChanges: true }>;
  /** GET /jmap/download/{accountId}/{blobId}/{name}: raw RFC 5322 bytes of an Email blob. */
  blobDownload(blobId: string, name?: string): Promise<ArrayBuffer>;
}

export default JmapClient;
