// Hand-written type declaration for compose.js. This is a SIDECAR .d.ts, not a converted module:
// compose.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists so client/test/*.test.ts get real type-checking on the send-path functions they drive
// headlessly. compose.js's much larger public surface (openCompose, refreshComposeNote, the rich
// editor wiring) is DOM-bound and not covered here because no TS-checked code imports it. It is
// not authoritative — if compose.js's behavior changes, this file must be updated by hand
// alongside it.

import type { Attach } from './store.js';

/** A compose draft, as $('#csend').onclick / the autosave path hand it to the send paths. */
export interface ComposeDraft {
  threadId?: string | null;
  replyThread?: string | null;
  to: string;
  subject?: string;
  body?: string;
  tier?: string;
  scheduleAt?: number | null;
  attach?: Attach[];
  /** The plain-text rendering of `body`, snapshotted at send time (stripped of any rich markup). */
  _text?: string;
}

/** Split on ASCII, full-width (，) and ideographic (、) commas — CJK keyboards type the latter two. */
export function splitRecips(s: string | null | undefined): string[];

/**
 * Dispatch a compose draft honestly by how the session could actually send at CLICK time.
 * `mode` is the caller's click-time snapshot; it wins over the live sendMode() so async mode
 * drift can't invert the user's intent.
 */
export function commitSend(draft: ComposeDraft, mode?: 'real' | 'seam' | 'sim'): Promise<void>;

/** REAL send over the node's Send API — one POST per recipient; see compose.js's header comment
 * for the exact honesty rules (attachments refused, rich text flattened, partial-failure drafts). */
export function commitSendReal(draft: ComposeDraft): Promise<void>;
