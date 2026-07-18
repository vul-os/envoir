// client/test/net.test.mjs — headless smoke tests for the client's network transports
// (js/net/send.js and js/net/jmap.js) under Node's built-in test runner. Zero dependencies,
// like the rest of the repo: node:test + node:assert only. Run with `npm run test:client`.
//
// The point of these tests is the WIRE CONTRACT, so every mock emits the node's exact shapes,
// cross-checked against the server code rather than invented:
//
//   POST /v1/send            → 200 {"id":"<hex>","native":bool,"transport":"..."} on success,
//                              {"error":"<slug>","detail":"..."} + status on failure
//                              (crates/dmtap-send/src/http.rs ok_response/error_slug,
//                               node/src/send_api.rs NodeDelivery: transport is
//                               "native-mesh" | "smtp-gateway"; statuses from
//                               SendError::http_status in crates/dmtap-send/src/key.rs)
//   GET /jmap/session        → the RFC 8620 Session resource
//                              (crates/dmtap-mail/src/jmap.rs session_resource)
//   POST /jmap/api/          → {"methodResponses":[[name,args,callId],...],"sessionState":"..."}
//                              (crates/dmtap-mail/src/jmap.rs Response; method-level failures
//                               come back as an ["error", {type}, callId] invocation, and
//                               Email/changes reports an unusable token as a SUCCESS-named
//                               invocation whose args are {"type":"cannotCalculateChanges"})
//
// `fetch` is mocked by plain assignment (globalThis.fetch = ...) and restored via t.after —
// no interception library. The modules under test are imported exactly as the browser loads
// them; that they import cleanly here is itself the "DOM-free" claim under test.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SendClient, SendApiError, sendMode, sendMail, DEFAULT_BASE_URL } from '../js/net/send.js';
import { JmapClient, JmapError, JmapResponse, CAP_CORE, CAP_MAIL, CAP_SUBMISSION } from '../js/net/jmap.js';
import { state, resolveNodeConfig } from '../js/store.js';
import { mergeLocalMail, syncNow, connect } from '../js/net/sync.js';
// compose.js is DOM-flavored but imports cleanly under Node (all document use is inside
// functions); the send paths under test only touch the DOM via toast(), stubbed by useDom().
import { commitSend, commitSendReal } from '../js/compose.js';

// ---- harness helpers ------------------------------------------------------------------------

// Swap in a fetch mock for one test, recording every call; restored automatically afterwards.
// `impl(url, init, n)` returns (or throws) what the mocked network does for call number n.
function useFetch(t, impl) {
  const calls = [];
  const prev = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const n = calls.push({ url: String(url), init });
    return impl(String(url), init, n);
  };
  t.after(() => { globalThis.fetch = prev; });
  return calls;
}

// A JSON Response exactly as the node writes it (Content-Type: application/json body).
const jsonRes = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// Patch a top-level field of the shared store state for one test; restored afterwards.
function patchState(t, key, value) {
  const prev = state[key];
  state[key] = value;
  t.after(() => { state[key] = prev; });
}

// Inject a host config (the Tauri seam resolveNodeConfig() prefers) for one test.
function injectNodeConfig(t, cfg) {
  const prev = globalThis.__ENVOIR_NODE__;
  globalThis.__ENVOIR_NODE__ = cfg;
  t.after(() => {
    if (prev === undefined) delete globalThis.__ENVOIR_NODE__;
    else globalThis.__ENVOIR_NODE__ = prev;
  });
}

// Stub the ONE DOM surface the compose send paths touch headlessly — ui.js toast() grabs
// document.getElementById('toast') and writes innerHTML. Returns the captured toast messages.
// (refreshComposeNote()'s document.querySelector also lands here and finds nothing — correct:
// no compose is open.) The pending auto-hide timer is cleared afterwards so tests exit cleanly.
function useDom(t) {
  const toasts = [];
  const toastEl = {
    _h: null,
    setAttribute() {},
    classList: { add() {}, remove() {}, toggle() {} },
    querySelector: () => null,
  };
  Object.defineProperty(toastEl, 'innerHTML', {
    set(v) { toasts.push(String(v)); },
    get() { return toasts[toasts.length - 1] || ''; },
  });
  const prev = globalThis.document;
  globalThis.document = { getElementById: () => toastEl, querySelector: () => null };
  t.after(() => {
    clearTimeout(toastEl._h);
    if (prev === undefined) delete globalThis.document;
    else globalThis.document = prev;
  });
  return toasts;
}

// The node's 200 receipt for POST /v1/send: a 33-byte content id in hex + the transport class
// (node/src/send_api.rs NodeDelivery).
const RECEIPT = { id: 'ab'.repeat(33), native: true, transport: 'native-mesh' };

// ---- SendClient: request shape + receipt ----------------------------------------------------

test('SendClient.send posts the exact /v1/send request and parses the receipt', async (t) => {
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));
  const client = new SendClient({ baseUrl: 'http://node.test:4700///', token: 'sk-cap-token' });

  const receipt = await client.send({
    from: 'you@node.test', to: 'bob@peer.example', subject: 'hi', body: 'hello', mime: 'raw-mime',
  });

  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  // Trailing slashes on the base URL are stripped; the route is fixed.
  assert.equal(url, 'http://node.test:4700/v1/send');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers.Authorization, 'Bearer sk-cap-token');
  assert.equal(init.headers['Content-Type'], 'application/json');
  assert.equal(init.headers.Accept, 'application/json');
  // The Resend-shaped body dmtap-send deserializes (crates/dmtap-send/src/http.rs).
  assert.deepEqual(JSON.parse(init.body), {
    from: 'you@node.test', to: 'bob@peer.example', subject: 'hi', body: 'hello', mime: 'raw-mime',
  });
  assert.deepEqual(receipt, RECEIPT);
});

test('SendClient.send omits mime when not provided and defaults from/subject/body to empty', async (t) => {
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));
  const client = new SendClient({ token: 'tok' });
  assert.equal(client.sendUrl, `${DEFAULT_BASE_URL}/v1/send`);

  await client.send({ to: 'bob@peer.example' });
  const body = JSON.parse(calls[0].init.body);
  // `mime` is an optional field server-side; an absent one must be ABSENT, not null/''.
  assert.deepEqual(body, { from: '', to: 'bob@peer.example', subject: '', body: '' });
});

test('SendClient.send fails closed before any network I/O without a token or recipient', async (t) => {
  const calls = useFetch(t, () => { throw new Error('must not be reached'); });

  await assert.rejects(
    () => new SendClient({}).send({ to: 'bob@peer.example' }),
    (e) => e instanceof SendApiError && e.slug === 'no_token',
  );
  await assert.rejects(
    () => new SendClient({ token: 'tok' }).send({}),
    (e) => e instanceof SendApiError && e.slug === 'bad_request',
  );
  assert.equal(calls.length, 0, 'a doomed send must never hit the wire');
});

// ---- SendClient: every node error slug → its human message ----------------------------------

// The node's full slug/status table (crates/dmtap-send: error_slug + SendError::http_status,
// plus the adapter-level bad_request) and the human sentence send.js maps each onto.
const NODE_ERRORS = [
  ['bad_request', 400, 'the message was rejected as malformed'],
  ['unauthorized', 401, 'the send token was rejected'],
  ['revoked', 401, 'the send token has been revoked'],
  ['expired', 401, 'the send token has expired'],
  ['not_yet_valid', 401, 'the send token is not yet valid'],
  ['wrong_issuer', 401, 'the send token was issued by a different node'],
  ['capability_invalid', 401, 'the send token is invalid'],
  ['out_of_scope', 403, 'this From address is outside the token’s scope'],
  ['rate_limited', 429, 'the send rate limit was hit — try again shortly'],
  ['unresolvable_recipient', 422, 'the recipient could not be resolved'],
  ['delivery_failed', 502, 'the node could not deliver the message'],
  ['build_failed', 500, 'the message could not be sealed'],
];

for (const [slug, status, message] of NODE_ERRORS) {
  test(`SendClient.send maps ${slug} (${status}) onto its human message`, async (t) => {
    useFetch(t, () => jsonRes(status, { error: slug, detail: `server detail for ${slug}` }));
    await assert.rejects(
      () => new SendClient({ token: 'tok' }).send({ to: 'bob@peer.example' }),
      (e) => {
        assert.ok(e instanceof SendApiError);
        assert.equal(e.slug, slug);
        assert.equal(e.status, status);
        assert.equal(e.detail, `server detail for ${slug}`);
        assert.equal(e.message, message);
        return true;
      },
    );
  });
}

test('SendClient.send surfaces an unknown slug via its detail — nothing is silently masked', async (t) => {
  useFetch(t, () => jsonRes(422, { error: 'brand_new_slug', detail: 'something specific went wrong' }));
  await assert.rejects(
    () => new SendClient({ token: 'tok' }).send({ to: 'bob@peer.example' }),
    (e) => e.slug === 'brand_new_slug' && e.message === 'something specific went wrong',
  );
});

test('SendClient.send handles a non-JSON error body with a synthetic http_<status> slug', async (t) => {
  useFetch(t, () => new Response('<html>gateway error</html>', { status: 503 }));
  await assert.rejects(
    () => new SendClient({ token: 'tok' }).send({ to: 'bob@peer.example' }),
    (e) => e instanceof SendApiError && e.slug === 'http_503' && e.status === 503
      && e.message === 'send failed (HTTP 503)',
  );
});

test('SendClient.send maps a transport failure onto the unreachable slug', async (t) => {
  useFetch(t, () => { throw new TypeError('fetch failed'); });
  await assert.rejects(
    () => new SendClient({ token: 'tok' }).send({ to: 'bob@peer.example' }),
    (e) => e instanceof SendApiError && e.slug === 'unreachable'
      && e.message === 'the node could not be reached' && e.detail === 'fetch failed',
  );
});

test('SendClient.send rejects a 200 whose body is not the receipt shape', async (t) => {
  // A 2xx without a string `id` is NOT a success — a failed send must never masquerade as one.
  useFetch(t, (u, i, n) => (n === 1
    ? new Response('not json', { status: 200 })
    : jsonRes(200, { ok: true })));
  const client = new SendClient({ token: 'tok' });
  await assert.rejects(() => client.send({ to: 'b@x' }), (e) => e.slug === 'malformed');
  await assert.rejects(() => client.send({ to: 'b@x' }), (e) => e.slug === 'malformed');
});

// ---- sendMode() / sendMail(): the app-facing tier logic -------------------------------------

test('sendMode is sim unless the store is in real mode', (t) => {
  patchState(t, 'net', { ...state.net, mode: 'sim' });
  assert.equal(sendMode(), 'sim');
});

test('sendMode is seam in real mode without a send token, real with one', (t) => {
  patchState(t, 'net', { ...state.net, mode: 'real' });
  // Drive resolveNodeConfig() through the injected-host seam so the test needs no localStorage.
  injectNodeConfig(t, { baseUrl: 'http://n.test:4700', username: 'you@n.test', appPassword: 'pw', sendToken: '' });
  assert.equal(sendMode(), 'seam');
  globalThis.__ENVOIR_NODE__.sendToken = 'sk-cap';
  assert.equal(sendMode(), 'real');
});

test('sendMail resolves the node config and defaults from to the connected account', async (t) => {
  patchState(t, 'net', { ...state.net, mode: 'real', accountId: 'you@n.test' });
  injectNodeConfig(t, { baseUrl: 'http://n.test:4700', username: 'login@n.test', appPassword: 'pw', sendToken: 'sk-cap' });
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));

  const receipt = await sendMail({ to: 'bob@peer.example', subject: 's', body: 'b' });
  assert.deepEqual(receipt, RECEIPT);
  assert.equal(calls[0].url, 'http://n.test:4700/v1/send');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer sk-cap');
  assert.equal(JSON.parse(calls[0].init.body).from, 'you@n.test');
});

test('sendMail without a configured send token fails closed before the wire', async (t) => {
  injectNodeConfig(t, { baseUrl: 'http://n.test:4700', username: 'you@n.test', appPassword: 'pw', sendToken: '' });
  const calls = useFetch(t, () => { throw new Error('must not be reached'); });
  await assert.rejects(() => sendMail({ to: 'bob@peer.example' }), (e) => e.slug === 'no_token');
  assert.equal(calls.length, 0);
});

// ---- JmapClient: session discovery, auth, request/response, errors --------------------------

// The node's Session resource, mirrored field-for-field from
// crates/dmtap-mail/src/jmap.rs session_resource() so the client is tested against the
// exact JSON the node serves at GET /jmap/session.
function sessionResource(accountId, baseUrl, stateToken) {
  return {
    capabilities: {
      [CAP_CORE]: {
        maxSizeUpload: 50000000, maxConcurrentUpload: 4, maxSizeRequest: 10000000,
        maxConcurrentRequests: 4, maxCallsInRequest: 16, maxObjectsInGet: 500,
        maxObjectsInSet: 500, collationAlgorithms: ['i;ascii-casemap', 'i;unicode-casemap'],
      },
      [CAP_MAIL]: {
        maxMailboxesPerEmail: null, maxMailboxDepth: null, maxSizeMailboxName: 200,
        maxSizeAttachmentsPerEmail: 50000000,
        emailQuerySortOptions: ['receivedAt', 'size', 'subject'],
        mayCreateTopLevelMailbox: true,
      },
      [CAP_SUBMISSION]: { maxDelayedSend: 0, submissionExtensions: {} },
    },
    accounts: {
      [accountId]: {
        name: accountId, isPersonal: true, isReadOnly: false,
        accountCapabilities: { [CAP_MAIL]: {}, [CAP_SUBMISSION]: {} },
      },
    },
    primaryAccounts: { [CAP_MAIL]: accountId, [CAP_SUBMISSION]: accountId },
    username: accountId,
    apiUrl: `${baseUrl}/jmap/api/`,
    downloadUrl: `${baseUrl}/jmap/download/{accountId}/{blobId}/{name}`,
    uploadUrl: `${baseUrl}/jmap/upload/{accountId}/`,
    eventSourceUrl: `${baseUrl}/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}`,
    state: stateToken,
  };
}

const expectedBasic = (user, pass) => 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');

test('JmapClient.discover sends Basic auth and adopts the advertised account + URLs', async (t) => {
  const calls = useFetch(t, () =>
    jsonRes(200, sessionResource('acct@node.test', 'http://node.test:4700', '7')));
  const client = new JmapClient({ baseUrl: 'http://node.test:4700', username: 'login@node.test', appPassword: 'app-pw' });

  const s = await client.discover();
  assert.equal(calls[0].url, 'http://node.test:4700/jmap/session');
  assert.equal(calls[0].init.headers.Authorization, expectedBasic('login@node.test', 'app-pw'));
  // primaryAccounts.<mail> wins over the login username for addressing method calls.
  assert.equal(client.accountId, 'acct@node.test');
  assert.equal(client.apiUrl, 'http://node.test:4700/jmap/api/');
  assert.equal(client.downloadUrl, 'http://node.test:4700/jmap/download/{accountId}/{blobId}/{name}');
  assert.equal(client.sessionState, '7');
  assert.equal(s.username, 'acct@node.test');
});

test('JmapClient Basic auth concatenates on the FIRST colon (RFC 7617)', (t) => {
  // An app-password may itself contain ':' — the credential must stay unambiguous.
  const client = new JmapClient({ username: 'you', appPassword: 'pa:ss:wd' });
  assert.equal(client.authHeader, expectedBasic('you', 'pa:ss:wd'));
});

test('JmapClient.discover surfaces 401 as a rejected app-password, other statuses as-is', async (t) => {
  useFetch(t, (u, i, n) => new Response('', { status: n === 1 ? 401 : 503 }));
  const client = new JmapClient({ username: 'you', appPassword: 'wrong' });
  await assert.rejects(() => client.discover(),
    (e) => e instanceof JmapError && e.status === 401 && /app-password/.test(e.message));
  await assert.rejects(() => client.discover(), (e) => e instanceof JmapError && e.status === 503);
});

test('JmapClient.ping is a boolean probe, never a throw', async (t) => {
  useFetch(t, (u, i, n) => {
    if (n === 1) return jsonRes(200, sessionResource('a@n', 'http://n:4700', '0'));
    throw new TypeError('fetch failed');
  });
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  assert.equal(await client.ping(), true);
  assert.equal(await client.ping(), false);
});

test('JmapClient.request posts the RFC 8620 envelope and parses methodResponses', async (t) => {
  // The node's exact response envelope: methodResponses + sessionState, nothing else
  // (crates/dmtap-mail/src/jmap.rs Response).
  const calls = useFetch(t, () => jsonRes(200, {
    methodResponses: [['Mailbox/get', { accountId: 'a@n', list: [], notFound: [] }, 'mb']],
    sessionState: '3',
  }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });

  const r = await client.request([['Mailbox/get', { accountId: 'a@n', ids: null }, 'mb']]);
  assert.equal(calls[0].url, `${client.baseUrl}/jmap/api/`);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers.Authorization, expectedBasic('a@n', 'pw'));
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    using: [CAP_CORE, CAP_MAIL, CAP_SUBMISSION],
    methodCalls: [['Mailbox/get', { accountId: 'a@n', ids: null }, 'mb']],
  });
  assert.ok(r instanceof JmapResponse);
  assert.equal(r.sessionState, '3');
  assert.deepEqual(r.arguments('mb'), { accountId: 'a@n', list: [], notFound: [] });
  assert.equal(r.arguments('missing'), null);
});

test('JmapClient.emailQueryGet chains query→get via a verbatim back-reference', async (t) => {
  const calls = useFetch(t, () => jsonRes(200, {
    methodResponses: [
      ['Email/query', { accountId: 'a@n', ids: ['e1'] }, 'q'],
      ['Email/get', { accountId: 'a@n', list: [{ id: 'e1' }], notFound: [] }, 'g'],
    ],
    sessionState: '3',
  }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });

  const got = await client.emailQueryGet(null, ['id', 'subject']);
  const sent = JSON.parse(calls[0].init.body);
  // The `#ids` ResultReference (RFC 8620 §3.7) must reach the node untouched — it resolves there.
  assert.deepEqual(sent.methodCalls[1][1]['#ids'], { resultOf: 'q', name: 'Email/query', path: '/ids' });
  assert.deepEqual(got.list, [{ id: 'e1' }]);
});

test('JmapResponse.arguments throws on a method-level error invocation', async (t) => {
  // RFC 8620 §3.6.1: a failed method comes back as ["error", {type}, callId]; it must never
  // read as an empty-but-ok result.
  useFetch(t, () => jsonRes(200, {
    methodResponses: [['error', { type: 'unknownMethod' }, 'q']],
    sessionState: '3',
  }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  const r = await client.request([['Bogus/get', {}, 'q']]);
  assert.throws(() => r.arguments('q'),
    (e) => e instanceof JmapError && e.message === 'method error: unknownMethod');
});

test('JmapClient.request rejects 401, non-2xx, and a body without methodResponses', async (t) => {
  useFetch(t, (u, i, n) => {
    if (n === 1) return new Response('', { status: 401 });
    if (n === 2) return jsonRes(500, { detail: 'boom' });
    return jsonRes(200, { notJmap: true });
  });
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  await assert.rejects(() => client.request([]), (e) => e instanceof JmapError && e.status === 401);
  await assert.rejects(() => client.request([]),
    (e) => e.status === 500 && e.body && e.body.detail === 'boom');
  await assert.rejects(() => client.request([]), (e) => /malformed JMAP response/.test(e.message));
});

test('JmapClient.emailChanges flags cannotCalculateChanges instead of faking an empty delta', async (t) => {
  // The node reports an unusable sinceState as a SUCCESS-named invocation whose args carry
  // {"type":"cannotCalculateChanges"} (crates/dmtap-mail/src/jmap.rs changes()) — NOT as an
  // ["error", ...] invocation. The client must map it to a full-repull signal.
  useFetch(t, () => jsonRes(200, {
    methodResponses: [['Email/changes', {
      type: 'cannotCalculateChanges',
      description: 'sinceState is not a recognizable state token',
    }, 'c']],
    sessionState: '3',
  }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  assert.deepEqual(await client.emailChanges('!!!bogus!!!'), { cannotCalculateChanges: true });
});

test('JmapClient.emailChanges returns the node delta shape verbatim', async (t) => {
  const delta = {
    accountId: 'a@n', oldState: '3', newState: '4', hasMoreChanges: false,
    created: ['e9'], updated: [], destroyed: [],
  };
  useFetch(t, () => jsonRes(200, { methodResponses: [['Email/changes', delta, 'c']], sessionState: '4' }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  assert.deepEqual(await client.emailChanges('3'), delta);
});

test('JmapClient.blobDownload builds the templated URL with encoded segments', async (t) => {
  const bytes = new TextEncoder().encode('From: a@n\r\n\r\nhi');
  const calls = useFetch(t, () => new Response(bytes, { status: 200 }));
  const client = new JmapClient({ username: 'a@n', appPassword: 'pw' });
  client.accountId = 'a@n';

  const buf = await client.blobDownload('INBOX|1', 'mail.eml');
  // The blob id contains '|' — it must be percent-encoded into the URL template.
  assert.equal(calls[0].url, `${client.baseUrl}/jmap/download/a%40n/INBOX%7C1/mail.eml`);
  assert.deepEqual(new Uint8Array(buf), bytes);

  useFetch(t, () => new Response('', { status: 404 }));
  await assert.rejects(() => client.blobDownload('nope'),
    (e) => e instanceof JmapError && e.status === 404);
});

// ---- resolveNodeConfig(): the injected-host vs Settings sendToken seam ----------------------

test('resolveNodeConfig: an injected config without a sendToken falls back to the saved settings token', (t) => {
  // The shell owns the CONNECTION; the user may still own the send CAPABILITY (pasted into
  // Settings → Node). An injected config lacking a token must not make that field dead UI.
  patchState(t, 'settings', { ...state.settings, node: { ...state.settings.node, sendToken: 'sk-user' } });
  injectNodeConfig(t, { baseUrl: 'http://shell.test:4700', username: 'shell@n', appPassword: 'shell-pw' });

  const cfg = resolveNodeConfig();
  assert.equal(cfg.baseUrl, 'http://shell.test:4700');   // connection: still the shell's
  assert.equal(cfg.appPassword, 'shell-pw');
  assert.equal(cfg.sendToken, 'sk-user');                // capability: the user's

  // ...but a token the shell DOES inject wins over the saved one.
  globalThis.__ENVOIR_NODE__.sendToken = 'sk-shell';
  assert.equal(resolveNodeConfig().sendToken, 'sk-shell');
});

test('resolveNodeConfig: an incomplete injected config yields the saved settings wholesale', (t) => {
  patchState(t, 'settings', { ...state.settings, node: { enabled: true, baseUrl: 'http://me.test:4700', username: 'me@n', appPassword: 'pw', sendToken: 'sk-user' } });
  injectNodeConfig(t, { baseUrl: 'http://shell.test:4700' });   // no username/appPassword → ignored
  const cfg = resolveNodeConfig();
  assert.equal(cfg.baseUrl, 'http://me.test:4700');
  assert.equal(cfg.sendToken, 'sk-user');
});

// ---- commitSendReal(): recipient fan-out, partial failure, attachment refusal ---------------

// A minimal compose draft as $('#csend').onclick hands it to the send paths.
const mkDraft = (over = {}) => ({
  threadId: null, replyThread: null, to: '', subject: 'subj', body: 'hello', tier: 'private',
  scheduleAt: null, attach: [], _text: 'hello', ...over,
});

// Real-mode session: live node + send token via the injected-host seam, empty mailbox.
function useRealSession(t) {
  patchState(t, 'mail', []);
  patchState(t, 'ui', { ...state.ui, selected: new Set() });
  patchState(t, 'net', { ...state.net, mode: 'real', accountId: 'you@n.test' });
  injectNodeConfig(t, { baseUrl: 'http://n.test:4700', username: 'you@n.test', appPassword: 'pw', sendToken: 'sk-cap' });
}

test('commitSendReal fans out one POST per recipient and records ALL of them as sent', async (t) => {
  useRealSession(t);
  const toasts = useDom(t);
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));

  await commitSendReal(mkDraft({ to: 'a@x, b@x, c@x' }));

  assert.deepEqual(calls.map((c) => JSON.parse(c.init.body).to), ['a@x', 'b@x', 'c@x']);
  assert.equal(state.mail.length, 1);
  const sent = state.mail[0];
  assert.equal(sent.folder, 'sent');
  assert.equal(sent.local, true, 'sent record is tagged local for the sync merge');
  assert.deepEqual(sent.msgs[0].to, ['a@x', 'b@x', 'c@x']);
  assert.deepEqual(sent.msgs[0].nodeIds, [RECEIPT.id, RECEIPT.id, RECEIPT.id]);
  // What the record claims is what went out: the plain-text body, no attachments.
  assert.equal(sent.msgs[0].html, false);
  assert.equal(sent.msgs[0].body, 'hello');
  assert.ok(toasts[toasts.length - 1].includes('Sent via your node'));
});

test('commitSendReal on PARTIAL failure records only accepted recipients and drafts the rest', async (t) => {
  useRealSession(t);
  const toasts = useDom(t);
  const calls = useFetch(t, (u, init) => (JSON.parse(init.body).to === 'b@x'
    ? jsonRes(422, { error: 'unresolvable_recipient', detail: 'no key for b@x' })
    : jsonRes(200, RECEIPT)));

  await commitSendReal(mkDraft({ to: 'a@x, b@x, c@x' }));

  assert.equal(calls.length, 3, 'a mid-list failure must not abort the rest of the fan-out');
  const sent = state.mail.find((th) => th.folder === 'sent');
  const draft = state.mail.find((th) => th.folder === 'drafts');
  assert.deepEqual(sent.msgs[0].to, ['a@x', 'c@x'], 'only actually-sent recipients are recorded');
  assert.deepEqual(sent.msgs[0].nodeIds, [RECEIPT.id, RECEIPT.id]);
  assert.deepEqual(draft.msgs[0].to, ['b@x'], 'the draft covers exactly the failed recipient');
  const last = toasts[toasts.length - 1];
  assert.ok(last.includes('b@x') && last.includes('the recipient could not be resolved'),
    'the toast names the failed recipient and the reason');
  assert.ok(last.includes('a@x') && last.includes('c@x'), 'the toast is honest about who WAS sent to');
});

test('commitSendReal with every recipient failing keeps the whole message in Drafts', async (t) => {
  useRealSession(t);
  const toasts = useDom(t);
  useFetch(t, () => jsonRes(502, { error: 'delivery_failed', detail: 'mesh down' }));

  await commitSendReal(mkDraft({ to: 'a@x, b@x' }));

  assert.equal(state.mail.length, 1);
  assert.equal(state.mail[0].folder, 'drafts');
  assert.deepEqual(state.mail[0].msgs[0].to, ['a@x', 'b@x']);
  assert.ok(toasts[toasts.length - 1].includes('kept in Drafts'));
});

test('commitSendReal REFUSES attachments — no wire I/O, kept in Drafts, honest toast', async (t) => {
  useRealSession(t);
  const toasts = useDom(t);
  const calls = useFetch(t, () => { throw new Error('must not be reached'); });

  await commitSendReal(mkDraft({ to: 'a@x', attach: [{ name: 'plan.pdf', size: 1234 }] }));

  assert.equal(calls.length, 0, 'an attachment send must never hit the wire');
  assert.equal(state.mail.length, 1);
  assert.equal(state.mail[0].folder, 'drafts');
  assert.deepEqual(state.mail[0].msgs[0].attach, [{ name: 'plan.pdf', size: 1234 }]);
  assert.ok(toasts[toasts.length - 1].includes("Attachments aren't supported over real send yet"));
});

test('commitSendReal sends rich text as plain text and says so', async (t) => {
  useRealSession(t);
  const toasts = useDom(t);
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));

  await commitSendReal(mkDraft({ to: 'a@x', body: 'hello <b>world</b>', _text: 'hello world' }));

  assert.equal(JSON.parse(calls[0].init.body).body, 'hello world');
  assert.equal(state.mail[0].msgs[0].html, false);
  assert.equal(state.mail[0].msgs[0].body, 'hello world');
  assert.ok(toasts[toasts.length - 1].includes('as plain text'),
    'the toast admits the formatting was not carried');
});

// ---- commitSend(): the click-time mode snapshot -----------------------------------------------

test('commitSend dispatches on the click-time snapshot, not the live (drifted) mode', async (t) => {
  useRealSession(t);   // live mode is REAL (with a token) …
  useDom(t);
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));

  // … but the user clicked Send when the session was still 'seam' → NO wire I/O, kept as draft.
  assert.equal(sendMode(), 'real');
  await commitSend(mkDraft({ to: 'bob@peer.example' }), 'seam');
  assert.equal(calls.length, 0, 'a seam-time click must not turn into a real send');
  assert.equal(state.mail.filter((th) => th.folder === 'drafts').length, 1);

  // A click taken in real mode genuinely sends, and the default snapshot is the live mode.
  await commitSend(mkDraft({ to: 'bob@peer.example' }), 'real');
  assert.equal(calls.length, 1);
  await commitSend(mkDraft({ to: 'carol@peer.example' }));
  assert.equal(calls.length, 2);
});

test('commitSend honors a real-mode snapshot even if the mode drifts back to sim', async (t) => {
  // The inverse drift: the user clicked Send while REAL; a disconnect during the undo window
  // must not downgrade their intended real send into a silent simulation.
  patchState(t, 'mail', []);
  patchState(t, 'ui', { ...state.ui, selected: new Set() });
  patchState(t, 'net', { ...state.net, mode: 'sim', accountId: null });
  injectNodeConfig(t, { baseUrl: 'http://n.test:4700', username: 'you@n.test', appPassword: 'pw', sendToken: 'sk-cap' });
  useDom(t);
  const calls = useFetch(t, () => jsonRes(200, RECEIPT));

  assert.equal(sendMode(), 'sim');
  await commitSend(mkDraft({ to: 'bob@peer.example' }), 'real');
  assert.equal(calls.length, 1, 'the click-time real snapshot still sends for real');
  assert.equal(state.mail[0].folder, 'sent');
});

// ---- mergeLocalMail() / syncNow(): real-mode rebuilds must not destroy local records ---------

// Client-shaped thread/message stubs for the merge tests.
const mkThread = (over = {}) => ({
  id: 't1', subject: 's', labels: [], folder: 'inbox', read: true, starred: false,
  snoozeUntil: null, tier: 'private', verified: false, legacy: false, msgs: [], ...over,
});
const mkMsg = (over = {}) => ({ id: 'm1', from: 'you', me: true, to: ['a@x'], time: 100, body: 'b', ...over });

test('mergeLocalMail carries local drafts and unserved sent threads over a rebuild', (t) => {
  const draft = mkThread({ id: 'tD', folder: 'drafts', local: true, msgs: [mkMsg({ id: 'mD' })] });
  const pending = mkThread({ id: 'tP', folder: 'sent', local: true, msgs: [mkMsg({ id: 'mP', nodeIds: ['not-served-yet'] })] });
  patchState(t, 'mail', [draft, pending]);

  const server = [mkThread({ id: 'T1', msgs: [mkMsg({ id: 'e1', from: 'ada@peer.example', me: false })] })];
  const merged = mergeLocalMail(server);
  assert.deepEqual(merged.map((th) => th.id).sort(), ['T1', 'tD', 'tP']);
});

test('mergeLocalMail drops a local sent thread once the server serves ALL its receipt ids', (t) => {
  const served = mkThread({ id: 'tS', folder: 'sent', local: true, msgs: [mkMsg({ id: 'mS', nodeIds: ['n1', 'n2'] })] });
  const half = mkThread({ id: 'tH', folder: 'sent', local: true, msgs: [mkMsg({ id: 'mH', nodeIds: ['n1', 'n9'] })] });
  patchState(t, 'mail', [served, half]);

  const server = [mkThread({ id: 'Tsent', folder: 'sent', msgs: [mkMsg({ id: 'n1' }), mkMsg({ id: 'n2' })] })];
  const merged = mergeLocalMail(server);
  assert.ok(!merged.some((th) => th.id === 'tS'), 'a fully-served sent record is not duplicated');
  assert.ok(merged.some((th) => th.id === 'tH'), 'a partially-served record is still the only copy — kept');
});

test('mergeLocalMail re-appends a local reply into its rebuilt server thread, without duplicates', (t) => {
  const reply = mkMsg({ id: 'mR', time: 500, local: true, nodeIds: ['r-77'] });
  patchState(t, 'mail', [mkThread({ id: 'T1', msgs: [mkMsg({ id: 'e1', time: 100 }), reply] })]);

  // Server rebuild without the reply → re-appended in chronological order.
  let merged = mergeLocalMail([mkThread({ id: 'T1', msgs: [mkMsg({ id: 'e1', time: 100 })] })]);
  assert.deepEqual(merged[0].msgs.map((m) => m.id), ['e1', 'mR']);

  // Server now serves the reply under its receipt id → NOT appended again.
  merged = mergeLocalMail([mkThread({ id: 'T1', msgs: [mkMsg({ id: 'e1', time: 100 }), mkMsg({ id: 'r-77', time: 500 })] })]);
  assert.deepEqual(merged[0].msgs.map((m) => m.id), ['e1', 'r-77']);
});

test('mergeLocalMail lets a server thread win when it adopts the local thread id', (t) => {
  patchState(t, 'mail', [mkThread({ id: 'T9', local: true, subject: 'local copy', msgs: [mkMsg()] })]);
  const merged = mergeLocalMail([mkThread({ id: 'T9', subject: 'server copy', msgs: [mkMsg({ id: 'srv' })] })]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].subject, 'server copy');
});

// A JMAP Email exactly as pullMail requests it (EMAIL_PROPS subset).
const jmapEmail = (over = {}) => ({
  id: 'e1', threadId: 'T1', mailboxIds: { mb1: true }, keywords: { $seen: true },
  receivedAt: '2026-07-01T10:00:00Z', subject: 'Server thread', size: 10, hasAttachment: false,
  from: [{ email: 'ada@peer.example' }], to: [{ email: 'you@n.test' }],
  textBody: [{ partId: 'p1' }], bodyValues: { p1: { value: 'server body' } },
  ...over,
});

test('syncNow rebuild preserves local drafts and dedupes a sent record the node now serves', async (t) => {
  // A hand-rolled client double standing in for JmapClient (syncNow only uses this surface).
  const fake = {
    accountId: 'you@n.test', sessionState: 's2',
    async discover() {},
    async mailboxGet() { return { list: [{ id: 'mb1', role: 'inbox', name: 'Inbox' }, { id: 'mbS', role: 'sent', name: 'Sent' }] }; },
    async emailQueryGet() {
      return { list: [
        jmapEmail(),
        // The node now serves the genuinely-sent message under its receipt (content) id.
        jmapEmail({ id: 'sent-1', threadId: 'Tsent', mailboxIds: { mbS: true }, subject: 'sent for real',
          from: [{ email: 'you@n.test' }], to: [{ email: 'ada@peer.example' }] }),
      ] };
    },
    async emailChanges() { return { created: ['sent-1'], updated: [], destroyed: [] }; },
  };
  patchState(t, 'ui', { ...state.ui, selThread: null, selected: new Set() });
  patchState(t, 'net', { ...state.net, mode: 'real', client: fake, sessionState: 's1', accountId: 'you@n.test' });
  patchState(t, 'mail', [
    mkThread({ id: 'tD', folder: 'drafts', local: true, msgs: [mkMsg({ id: 'mD', time: 900 })] }),
    mkThread({ id: 'tS', folder: 'sent', local: true, msgs: [mkMsg({ id: 'mS', time: 800, nodeIds: ['sent-1'] })] }),
  ]);

  const res = await syncNow();
  assert.equal(res.ok, true);
  const ids = state.mail.map((th) => th.id).sort();
  assert.deepEqual(ids, ['T1', 'Tsent', 'tD'], 'draft carried; served sent record deduped, not doubled');
  const servedCopies = state.mail.filter((th) => th.msgs.some((m) => String(m.id) === 'sent-1'
    || (Array.isArray(m.nodeIds) && m.nodeIds.includes('sent-1'))));
  assert.equal(servedCopies.length, 1, 'exactly one copy of the sent message survives');
});

// The full JMAP wire for connect(): session discovery + Mailbox/get + Email/query→get, using the
// node's exact envelopes (call ids 'mb'/'q'/'g' match net/jmap.js).
function useJmapNode(t, emails) {
  return useFetch(t, (url, init) => {
    if (url.endsWith('/jmap/session')) {
      return jsonRes(200, sessionResource('you@n.test', 'http://n.test:4700', '1'));
    }
    const req = JSON.parse(init.body);
    if (req.methodCalls[0][0] === 'Mailbox/get') {
      return jsonRes(200, {
        methodResponses: [['Mailbox/get', { accountId: 'you@n.test', list: [{ id: 'mb1', role: 'inbox', name: 'Inbox' }], notFound: [] }, 'mb']],
        sessionState: '1',
      });
    }
    return jsonRes(200, {
      methodResponses: [
        ['Email/query', { accountId: 'you@n.test', ids: emails.map((e) => e.id) }, 'q'],
        ['Email/get', { accountId: 'you@n.test', list: emails, notFound: [] }, 'g'],
      ],
      sessionState: '1',
    });
  });
}

const NODE_CFG = { baseUrl: 'http://n.test:4700', username: 'you@n.test', appPassword: 'pw' };

test('connect from SIMULATION replaces the store wholesale — sim data never leaks into real mode', async (t) => {
  patchState(t, 'ui', { ...state.ui, selThread: null, selected: new Set() });
  patchState(t, 'net', { ...state.net, mode: 'sim', client: null });
  patchState(t, 'mail', [mkThread({ id: 'tSim', folder: 'drafts', local: true, msgs: [mkMsg()] })]);
  useJmapNode(t, [jmapEmail()]);

  const res = await connect(NODE_CFG);
  assert.equal(res.ok, true);
  assert.deepEqual(state.mail.map((th) => th.id), ['T1'], 'sim-era threads (even local ones) are replaced');
});

test('reconnect while REAL carries locally-originated threads over the rebuild', async (t) => {
  patchState(t, 'ui', { ...state.ui, selThread: null, selected: new Set() });
  patchState(t, 'net', { ...state.net, mode: 'real', client: {}, accountId: 'you@n.test' });
  patchState(t, 'mail', [mkThread({ id: 'tD', folder: 'drafts', local: true, msgs: [mkMsg({ id: 'mD' })] })]);
  useJmapNode(t, [jmapEmail()]);

  const res = await connect(NODE_CFG);
  assert.equal(res.ok, true);
  assert.deepEqual(state.mail.map((th) => th.id).sort(), ['T1', 'tD'],
    'a reconnect must not destroy the just-composed draft');
});
