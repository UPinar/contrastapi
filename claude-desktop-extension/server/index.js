#!/usr/bin/env node
// ContrastAPI Desktop Extension — stdio <-> Streamable HTTP bridge.
// Forwards JSON-RPC messages verbatim between the host (Claude Desktop, stdio)
// and the remote ContrastAPI MCP server. The only non-passthrough logic:
//   - application errors (HTTP 4xx like rate-limit 429 / bad-key 401) become a
//     JSON-RPC error reply to the host — NOT a reconnect (the session is fine);
//     the remote's own upsell body is forwarded when well-formed.
//   - a dropped/restarted remote (daily blue/green bounce) is silently
//     re-established by a SINGLE driver (the reconnect loop): re-send initialize,
//     await its response, replay initialized + buffered/pending traffic in arrival
//     order, drain anything that arrived mid-replay, then mark ready. Bounded by an
//     attempt cap. No separate poll loop and no cross-driver shared-state races.

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const DEFAULT_URL = 'https://api.contrastcyber.com/mcp/';
const REMOTE_URL = (process.env.CONTRASTAPI_URL || DEFAULT_URL).trim();
const API_KEY = (process.env.CONTRASTAPI_API_KEY || '').trim();
const TRUSTED_HOST = 'api.contrastcyber.com';
const SEND_TIMEOUT_MS = 120_000; // upper bound on a forwarded POST (host has its own UX timeout)
const RECONNECT_TIMEOUT_MS = 20_000; // bound a stalled re-init/replay send so the retry loop can't freeze
const MAX_RECONNECT_ATTEMPTS = 6;
const MAX_ERR_MESSAGE = 2000; // cap on a forwarded remote error message

const log = (...a) => console.error('[contrastapi]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Remote-controlled text (error bodies) may reach a log the user is told to read —
// strip control chars and cap length so it can't inject terminal escapes or giant lines.
const safe = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, 200);

// --- URL / key safety (B7) -------------------------------------------------
let remoteUrl;
try {
  remoteUrl = new URL(REMOTE_URL);
} catch {
  log('invalid CONTRASTAPI_URL, exiting');
  process.exit(1);
}
const isLocalhost = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(remoteUrl.hostname);
if (remoteUrl.protocol !== 'https:' && !(remoteUrl.protocol === 'http:' && isLocalhost)) {
  log(`refusing non-HTTPS remote URL (${remoteUrl.protocol}//${remoteUrl.hostname}), exiting`);
  process.exit(1);
}
// Attach the API key ONLY to the trusted host (or an explicit localhost dev target),
// so an env-var override can't exfiltrate the keychain-held key to an attacker host.
const sendKey = Boolean(API_KEY) && (remoteUrl.hostname === TRUSTED_HOST || isLocalhost);

// --- state -----------------------------------------------------------------
let http = null; // current transport; a captured `transport` is compared against it to drop stale deliveries
let ready = false; // remote session usable (host traffic flows straight through)
let reconnecting = false;
let shuttingDown = false;
let reconnectAttempts = 0;

let initializeMsg = null; // host's initialize request, re-sent on reconnect
let initializedNote = null; // host's notifications/initialized, replayed on reconnect
let awaitingInit = null; // {resolve, reject, forward, transport} during a reconnect handshake
const pending = new Map(); // id -> request awaiting a response; replayed after a reconnect
let sendQueue = []; // messages received while down, in arrival order; replayed head-first

const stdio = new StdioServerTransport();

function makeTransport() {
  const headers = {};
  if (sendKey) headers['X-API-Key'] = API_KEY;
  // redirect:'error' — never let the API key follow a cross-origin redirect (fetch keeps
  // custom headers across redirects), so a compromised/misconfigured host can't harvest it.
  return new StreamableHTTPClientTransport(new URL(REMOTE_URL), { requestInit: { headers, redirect: 'error' } });
}

// Reject if `p` doesn't settle within `ms`. The underlying fetch is not aborted
// here (the SDK owns its signal); a subsequent transport.close() aborts it.
function withTimeout(p, ms) {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error(`timeout after ${ms}ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

const httpStatus = (e) => (e && typeof e.code === 'number' && e.code > 0 ? e.code : null);
// 4xx (except 404 = session gone) is an application answer, not a broken connection.
const isAppError = (status) => status !== null && status >= 400 && status < 500 && status !== 404;

// The SDK embeds the response body in the thrown error message; recover the
// remote's own JSON-RPC error (carries the rate-limit retry_after / upgrade_url).
function remoteErrorBody(e) {
  const m = /Error POSTing to endpoint: ([\s\S]*)$/.exec(e?.message || '');
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch {
    return null;
  }
}

// Turn an application-level HTTP error into a JSON-RPC error reply to the host, so a
// rate-limit / bad-key surfaces as a normal tool error instead of a hang + reconnect.
async function replyAppError(msg, status, e) {
  if (msg.id === undefined) {
    log('remote rejected notification with HTTP', status);
    return;
  }
  const remoteErr = remoteErrorBody(e)?.error;
  // Forward only a well-formed, bounded error object; otherwise synthesize a clean one.
  const error =
    remoteErr &&
    typeof remoteErr.code === 'number' &&
    typeof remoteErr.message === 'string' &&
    remoteErr.message.length <= MAX_ERR_MESSAGE
      ? remoteErr
      : { code: -32000, message: `Upstream returned HTTP ${status}` };
  pending.delete(msg.id);
  await stdio.send({ jsonrpc: '2.0', id: msg.id, error }).catch((se) => log('stdio send failed:', safe(se?.message)));
}

// Send one message to the remote. Returns on delivery or after replying an application
// error (session stays up); throws on a connection-level failure (caller triggers reconnect).
async function sendToRemote(msg, timeoutMs) {
  try {
    await withTimeout(http.send(msg), timeoutMs);
  } catch (e) {
    const status = httpStatus(e);
    if (isAppError(status)) {
      await replyAppError(msg, status, e);
      return;
    }
    throw e;
  }
}

function onHostMessage(msg) {
  if (msg.method === 'initialize') initializeMsg = msg;
  if (msg.method === 'notifications/initialized') initializedNote = msg;
  if (msg.id !== undefined && msg.method) pending.set(msg.id, msg);
  // A cancel drops its target from BOTH the pending set and any un-sent queued copy,
  // so a request cancelled while down isn't re-run (and re-billed) on reconnect.
  if (msg.method === 'notifications/cancelled' && msg.params?.requestId !== undefined) {
    const rid = msg.params.requestId;
    pending.delete(rid);
    sendQueue = sendQueue.filter((m) => !(m.id === rid && m.method));
  }
  if (!ready) {
    sendQueue.push(msg);
    return;
  }
  sendToRemote(msg, SEND_TIMEOUT_MS).catch((e) => {
    // Connection-level failure: a request survives in `pending`; a notification/response
    // must be re-buffered here or it would be lost (never replayed).
    if (msg.id === undefined || !msg.method) queueForReplay(msg);
    onRemoteFailure(e);
  });
}

function queueForReplay(msg) {
  if (!sendQueue.includes(msg)) sendQueue.push(msg);
}

async function onRemoteMessage(msg, transport) {
  if (transport !== http) return; // drop late deliveries from a superseded transport (generation guard)
  // Reconnect handshake: the response to our re-sent initialize.
  if (
    awaitingInit &&
    awaitingInit.transport === transport &&
    msg.id === initializeMsg?.id &&
    (msg.result !== undefined || msg.error !== undefined)
  ) {
    const { resolve, reject, forward } = awaitingInit;
    awaitingInit = null;
    if (forward) {
      // The host's original initialize was never answered — deliver this response, don't swallow it.
      pending.delete(msg.id);
      await stdio.send(msg).catch((e) => log('stdio send failed:', safe(e?.message)));
    }
    if (msg.error) reject(new Error(`re-init rejected: ${safe(JSON.stringify(msg.error))}`));
    else resolve();
    return;
  }
  if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
    pending.delete(msg.id);
  }
  await stdio.send(msg).catch((e) => log('stdio send failed:', safe(e?.message)));
}

// Replay after a successful re-initialize (same transport): initialized, then pending
// requests (older-first), then the arrival-ordered queue drained to empty. Runs inside
// the reconnect driver; throws on a connection-level failure so the loop retries. Items
// leave `sendQueue` only once sent, so a mid-replay failure leaves the rest buffered and
// host traffic arriving mid-replay is picked up before `ready` flips.
async function completeReplay(transport) {
  const sentNote = initializedNote; // capture: a NEW note arriving mid-drain must still be sent, not skipped
  if (sentNote) {
    try {
      await withTimeout(transport.send(sentNote), RECONNECT_TIMEOUT_MS);
    } catch (e) {
      if (!isAppError(httpStatus(e))) throw e; // connection-level → fail the session, retry
      log('re-init notification returned HTTP error, continuing:', safe(e?.message));
    }
  }
  const excludeId = initializeMsg?.id; // already sent as the handshake message (no double-init)
  const queuedReqIds = new Set(sendQueue.filter((m) => m.id !== undefined && m.method).map((m) => m.id));
  const olderPending = [...pending.values()].filter((m) => m.id !== excludeId && !queuedReqIds.has(m.id));
  for (const m of olderPending) {
    await sendToRemote(m, RECONNECT_TIMEOUT_MS); // on throw: request persists in `pending`, retried next cycle
  }
  while (sendQueue.length > 0) {
    const m = sendQueue[0]; // peek — remove only after a successful send so a throw leaves it buffered
    // Skip only the handshake initialize request (needs `method` — a response with a colliding id
    // must not be dropped) and the initialized note already sent above.
    if ((m.method && m.id === excludeId) || m === sentNote) {
      sendQueue.shift();
      continue;
    }
    await sendToRemote(m, RECONNECT_TIMEOUT_MS);
    // Shift by identity: a concurrent notifications/cancelled may have filtered `m` out of the
    // queue during the await, in which case `m` is already gone and the head is a different message.
    if (sendQueue[0] === m) sendQueue.shift();
  }
  ready = true; // no await between the empty-queue check and here → host traffic can't slip past the drain
  reconnectAttempts = 0; // only after a fully successful replay — so the cap actually bounds the loop
  log('session re-established');
}

async function onRemoteFailure(err) {
  if (shuttingDown) return;
  if (reconnecting) {
    ready = false;
    return;
  }
  reconnecting = true;
  ready = false;
  log('remote connection lost:', safe(err?.message || err));
  if (!initializeMsg) {
    log('failed before first initialize, exiting');
    process.exit(1);
  }
  while (!shuttingDown && !ready) {
    try {
      await http?.close(); // drop the prior/failed transport before making a new one
    } catch {
      /* already dead */
    }
    reconnectAttempts++;
    if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
      log('unable to re-establish session, exiting');
      process.exit(1);
    }
    await sleep(Math.min(500 * 2 ** reconnectAttempts, 15_000));
    try {
      await connectRemote(true); // sends init, awaits response, replays, sets ready — all in this driver
    } catch (e) {
      log('reconnect attempt failed:', safe(e?.message || e));
    }
  }
  reconnecting = false;
}

async function connectRemote(isReconnect) {
  const transport = makeTransport();
  transport.onmessage = (msg) => onRemoteMessage(msg, transport);
  transport.onerror = (e) => log('remote error:', safe(e?.message || e));
  transport.onclose = () => {
    if (!shuttingDown && ready && transport === http) onRemoteFailure(new Error('remote connection closed'));
  };
  http = transport;
  await transport.start();
  if (!(isReconnect && initializeMsg)) {
    ready = true; // first connect: the host drives initialize itself
    return;
  }
  // Reconnect handshake. If the host's original initialize was never answered (still in
  // `pending`), forward this response instead of swallowing it, or the host hangs on startup.
  const forward = pending.has(initializeMsg.id);
  const initDone = new Promise((resolve, reject) => {
    awaitingInit = { resolve, reject, forward, transport };
  });
  await withTimeout(transport.send(initializeMsg), RECONNECT_TIMEOUT_MS);
  await withTimeout(initDone, RECONNECT_TIMEOUT_MS);
  await completeReplay(transport);
}

async function main() {
  stdio.onmessage = onHostMessage;
  stdio.onerror = (e) => log('stdio error:', safe(e?.message || e));
  stdio.onclose = async () => {
    shuttingDown = true;
    try {
      await http?.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  };
  await connectRemote(false);
  await stdio.start();
  if (API_KEY && !sendKey) log(`API key set but remote host is not ${TRUSTED_HOST} — key will NOT be sent`);
  log(`bridging stdio <-> ${remoteUrl.protocol}//${remoteUrl.host} ${sendKey ? '(Pro key set)' : '(keyless free tier)'}`);
}

main().catch((e) => {
  log('fatal:', safe(e?.message || e));
  process.exit(1);
});
