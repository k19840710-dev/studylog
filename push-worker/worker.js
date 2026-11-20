/**
 * StudyLog 通知サーバー (Cloudflare Workers)
 *
 * アプリから「◯時◯分に通知して」という予約を受け取り、1分ごとの Cron で時間になった予約を
 * Web プッシュ通知として送る。通知の暗号化と署名 (VAPID) の鍵は、初回に自動で作って KV に保存する。
 *
 * 必要な設定 (Cloudflare の管理画面)
 *   - KV のバインディング: 変数名 QUEUE
 *   - Cron トリガー: * * * * *  (1分ごと)
 *
 * API
 *   GET  /vapid               → { publicKey }
 *   POST /schedule            { subscription, at, title, body }  … 端末ごとに予約は1件 (新しい予約で上書き)
 *   POST /cancel              { endpoint }
 */

const ALLOWED_ORIGINS = [
  'https://k19840710-dev.github.io',
  'http://localhost:8765'
];
// 通知を送ってよい送り先 (各ブラウザのプッシュサービス)
const PUSH_HOSTS = [/^web\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /\.notify\.windows\.com$/];
const VAPID_SUBJECT = 'https://k19840710-dev.github.io/studylog/';
const MAX_QUEUE = 300;            // 予約の最大件数 (いたずら対策)
const MAX_AHEAD_MS = 12 * 3600e3; // 12時間より先の予約は受け付けない

// ---------- 小さな道具 ----------
const enc = new TextEncoder();
function b64u(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8));
}

// ---------- VAPID の鍵 (初回に作って KV に保存) ----------
async function getVapid(env) {
  const saved = await env.QUEUE.get('vapid', 'json');
  if (saved) return saved;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const vapid = {
    privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
    publicKey: b64u(await crypto.subtle.exportKey('raw', pair.publicKey))
  };
  await env.QUEUE.put('vapid', JSON.stringify(vapid));
  return vapid;
}

async function vapidHeader(vapid, endpoint) {
  const header = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: VAPID_SUBJECT
  })));
  const key = await crypto.subtle.importKey('jwk', vapid.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${vapid.publicKey}`;
}

// ---------- 通知の中身の暗号化 (RFC 8291 / aes128gcm) ----------
async function encryptPayload(subscription, payload) {
  const uaPublic = unb64u(subscription.keys.p256dh);
  const authSecret = unb64u(subscription.keys.auth);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));

  const ikm = await hkdf(authSecret, ecdh, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plain = concat(enc.encode(payload), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plain));

  const rs = new Uint8Array([0, 0, 16, 0]); // レコードサイズ 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

async function sendPush(env, vapid, item) {
  const body = await encryptPayload(item.subscription, JSON.stringify({ title: item.title, body: item.body }));
  const res = await fetch(item.subscription.endpoint, {
    method: 'POST',
    headers: {
      Authorization: await vapidHeader(vapid, item.subscription.endpoint),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      TTL: '600',
      Urgency: 'high'
    },
    body
  });
  return res.status;
}

// ---------- 予約の保存 (KV のキー1つに配列で持つ) ----------
async function loadQueue(env) {
  return (await env.QUEUE.get('queue', 'json')) || [];
}
async function saveQueue(env, queue) {
  await env.QUEUE.put('queue', JSON.stringify(queue));
}

function validSubscription(s) {
  if (!s || typeof s.endpoint !== 'string' || !s.keys || typeof s.keys.p256dh !== 'string' || typeof s.keys.auth !== 'string') return false;
  let url;
  try { url = new URL(s.endpoint); } catch (e) { return false; }
  return url.protocol === 'https:' && PUSH_HOSTS.some(re => re.test(url.hostname))
    && s.endpoint.length < 1000 && s.keys.p256dh.length < 200 && s.keys.auth.length < 100;
}
const text = (v, max) => (typeof v === 'string' ? v : '').slice(0, max);

// ---------- 入口 ----------
function cors(request) {
  const origin = request.headers.get('Origin') || '';
  const h = { 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400', Vary: 'Origin' };
  if (ALLOWED_ORIGINS.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}
function json(request, data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...cors(request) } });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(request) });
    const path = new URL(request.url).pathname;

    if (request.method === 'GET' && path === '/vapid') {
      const vapid = await getVapid(env);
      return json(request, { publicKey: vapid.publicKey });
    }
    if (request.method === 'GET' && path === '/') {
      return json(request, { ok: true, service: 'StudyLog push' });
    }
    if (request.method !== 'POST') return json(request, { error: 'not found' }, 404);

    let data;
    try { data = await request.json(); } catch (e) { return json(request, { error: 'bad json' }, 400); }

    if (path === '/schedule') {
      const at = Number(data.at);
      if (!validSubscription(data.subscription)) return json(request, { error: 'bad subscription' }, 400);
      if (!Number.isFinite(at) || at < Date.now() - 60e3 || at > Date.now() + MAX_AHEAD_MS) return json(request, { error: 'bad time' }, 400);
      const sub = { endpoint: data.subscription.endpoint, keys: { p256dh: data.subscription.keys.p256dh, auth: data.subscription.keys.auth } };
      let queue = (await loadQueue(env)).filter(q => q.subscription.endpoint !== sub.endpoint);
      if (queue.length >= MAX_QUEUE) return json(request, { error: 'busy' }, 429);
      queue.push({ subscription: sub, at, title: text(data.title, 60) || 'StudyLog', body: text(data.body, 120) });
      await saveQueue(env, queue);
      return json(request, { ok: true });
    }
    if (path === '/cancel') {
      if (typeof data.endpoint !== 'string') return json(request, { error: 'bad endpoint' }, 400);
      const queue = await loadQueue(env);
      const next = queue.filter(q => q.subscription.endpoint !== data.endpoint);
      if (next.length !== queue.length) await saveQueue(env, next);
      return json(request, { ok: true });
    }
    return json(request, { error: 'not found' }, 404);
  },

  // 1分ごと: 時間になった予約を送る
  async scheduled(event, env) {
    const queue = await loadQueue(env);
    const now = Date.now();
    const due = queue.filter(q => q.at <= now + 20e3); // 次の確認まで待つと遅れすぎる分は前倒しで送る
    if (due.length === 0) return;
    const vapid = await getVapid(env);
    await Promise.all(due.map(async item => {
      try { await sendPush(env, vapid, item); } catch (e) { /* 送れなかったものは捨てる */ }
    }));
    // 送っている間に入った新しい予約を消さないよう、読み直してから送った分だけ取り除く
    const latest = await loadQueue(env);
    const sent = new Set(due.map(q => q.subscription.endpoint + '|' + q.at));
    await saveQueue(env, latest.filter(q => !sent.has(q.subscription.endpoint + '|' + q.at)));
  }
};
