// Hand-written type declaration for net/send.js. This is a SIDECAR .d.ts, not a converted
// module: net/send.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This
// file exists only so client/test/net.test.ts gets real type-checking on the wire-facing
// SendClient surface. It describes send.js's PUBLIC exports as implemented; it is not
// authoritative — if send.js's behavior changes, this file must be updated by hand alongside it.

/** Default node base URL when none is configured. */
export const DEFAULT_BASE_URL: string;

export interface SendApiErrorOptions {
  status?: number;
  slug?: string | null;
  detail?: string | null;
}

/** A Send-API error carrying the HTTP status, the node's machine-readable slug, and its detail. */
export class SendApiError extends Error {
  status: number;
  slug: string | null;
  detail: string | null;
  constructor(message: string, opts?: SendApiErrorOptions);
}

export interface SendClientConfig {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
}

/**
 * The Resend-shaped body POST /v1/send expects (spec §13.5.1). `to` is typed optional, not
 * required: send.js validates a missing/falsy `to` at RUNTIME (throwing the `bad_request` slug)
 * rather than via a default parameter, so callers — including the deliberately-invalid-input
 * tests exercising that validation — can omit it.
 */
export interface SendMessageInput {
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  mime?: string;
}

/** The node's receipt on a successful send. */
export interface SendReceipt {
  id: string;
  native: boolean;
  transport: string | null;
}

/** A live client for the node's Envoir Send API. DOM-free / state-free. */
export class SendClient {
  baseUrl: string;
  token: string;
  timeoutMs: number;
  sendUrl: string;
  constructor(cfg?: SendClientConfig);
  send(msg: SendMessageInput): Promise<SendReceipt>;
}

/**
 * The honest send capability of the current session: 'real' | 'seam' | 'sim'
 * (see send.js's own doc comment for the exact meaning of each).
 */
export function sendMode(): 'real' | 'seam' | 'sim';

export interface SendMailInput {
  from?: string;
  to: string;
  subject?: string;
  body?: string;
  mime?: string;
}

/** Send `msg` for real via the node's Send API, defaulting `from` to the connected account. */
export function sendMail(msg?: SendMailInput): Promise<SendReceipt>;

export default SendClient;
