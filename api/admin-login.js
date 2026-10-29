'use strict';
/**
 * ERG — دخول الإدارة بالرمز (المصادقة ← كود المدير ← المصادقة) — Vercel Serverless
 *
 * لماذا: مع legacyMode() = false لم يعد المتصفح (الجلسة المجهولة) قادراً على قراءة
 * config/admin_settings (الهاش والملح ومفتاح المصادقة)، فتوقف التحقق من جهة العميل.
 * الحل: التحقق كله هنا في الخادم، ثم يصدر رمز دخول مخصّص لحساب المدير نفسه
 * (فتنطبق عليه صلاحيات memberships كما في الدخول بالبريد، بلا تعديل على القواعد).
 *
 * المراحل (تُرسَل كلها إلى POST /api/admin-login):
 *   step 1: otp                → يعيد stage (يثبت المصادقة الأولى)
 *   step 2: code + stage       → يعيد stage جديد (needOtp) أو الرمز النهائي إن كانت المصادقة معطلة
 *   step 3: otp + stage        → يعيد الرمز النهائي token
 *
 * متغيرات البيئة: FIREBASE_SERVICE_ACCOUNT , APP_ID (اختياري)
 *   ADMIN_UID (اختياري): معرّف حساب المدير؛ إن غاب يُؤخذ من memberships إن وُجد مدير واحد فقط.
 *   ADMIN_STAGE_SECRET (اختياري): سر توقيع المراحل؛ إن غاب يُشتق من حساب الخدمة.
 *
 * يُنشر باسم api/admin-login.js بجانب api/login-v2.js.
 */
const crypto = require('crypto');
const OTPAuth = require('otpauth');

const APP_ID = process.env.APP_ID || 'erg2024';
const BASE = `artifacts/${APP_ID}/public/data`;
const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_IP = 8;
const MAX_FAILS_GLOBAL = 40;
const STAGE_TTL_MS = 5 * 60 * 1000;

const sha256Hex = (text, salt) => crypto.createHash('sha256').update(String(text) + String(salt), 'utf8').digest('hex');
function safeEq(a, b) {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function clientIp(req) {
    const xf = (req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip'])) || '';
    return String(xf).split(',')[0].trim() || 'unknown';
}
function validateTotp(secret, token, atMs) {
    try {
        const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(String(secret).replace(/\s+/g, '').toUpperCase()), algorithm: 'SHA1', digits: 6, period: 30 });
        return totp.validate({ token: String(token || '').trim(), window: 2, timestamp: atMs }) !== null;
    } catch (e) { return false; }
}

function makeHandler({ getDb, getAuth, now = () => Date.now(), stageSecret }) {
    const secret = () => stageSecret || process.env.ADMIN_STAGE_SECRET
        || (process.env.FIREBASE_SERVICE_ACCOUNT ? sha256Hex('admin-stage', process.env.FIREBASE_SERVICE_ACCOUNT) : '');
    const sign = (payload) => {
        const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
        return p + '.' + crypto.createHmac('sha256', secret()).update(p).digest('base64url');
    };
    const readStage = (tok, ip) => {
        try {
            const [p, sig] = String(tok || '').split('.');
            if (!p || !sig) return null;
            const good = crypto.createHmac('sha256', secret()).update(p).digest('base64url');
            if (!safeEq(sig, good)) return null;
            const d = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
            if (!d.exp || now() > d.exp || d.ip !== sha256Hex(ip, 'stage-ip')) return null;
            return d;
        } catch (e) { return null; }
    };
    const send = (res, status, body) => { res.setHeader('Cache-Control', 'no-store'); res.status(status).json(body); };

    async function blockedFor(db, tid, max) {
        const snap = await db.doc(`${BASE}/login_attempts/${tid}`).get();
        if (!snap.exists) return 0;
        const d = snap.data();
        if (now() - (d.firstAt || 0) > WINDOW_MS) return 0;
        return (d.count || 0) >= max ? Math.ceil((WINDOW_MS - (now() - d.firstAt)) / 1000) : 0;
    }
    async function recordFail(db, tid) {
        const ref = db.doc(`${BASE}/login_attempts/${tid}`);
        await db.runTransaction(async (tx) => {
            const snap = await tx.get(ref); const d = snap.exists ? snap.data() : null; const t = now();
            if (!d || t - (d.firstAt || 0) > WINDOW_MS) tx.set(ref, { count: 1, firstAt: t });
            else tx.set(ref, { count: (d.count || 0) + 1, firstAt: d.firstAt });
        });
    }
    async function adminUid(db) {
        if (process.env.ADMIN_UID) return process.env.ADMIN_UID;
        const q = await db.collection(`${BASE}/memberships`).where('role', '==', 'master').limit(2).get();
        return q.size === 1 ? q.docs[0].id : null;
    }

    return async function handler(req, res) {
        try {
            if (!secret()) return send(res, 503, { error: 'not_configured' });
            const db = getDb();
            if (req.method === 'GET') {
                const a = await db.doc(`${BASE}/config/admin_settings`).get();
                const ok = !!(a.exists && a.data().masterHash && a.data().masterSalt);
                return send(res, ok ? 200 : 503, { ok, version: 1 });
            }
            if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
            let body = req.body;
            if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
            body = body || {};
            const step = Number(body.step);
            const otp = typeof body.otp === 'string' ? body.otp.trim() : '';
            const code = typeof body.code === 'string' ? body.code.trim() : '';
            if (![1, 2, 3].includes(step) || code.length > 100 || otp.length > 12 || /[\u0000-\u001f]/.test(code)) {
                return send(res, 400, { error: 'bad_request' });
            }

            const ip = clientIp(req);
            const ipTid = sha256Hex(ip + '|admin', 'throttle').slice(0, 40);
            const glTid = sha256Hex('global|admin', 'throttle').slice(0, 40);
            const w1 = await blockedFor(db, ipTid, MAX_FAILS_IP);
            const w2 = w1 ? 0 : await blockedFor(db, glTid, MAX_FAILS_GLOBAL);
            if (w1 || w2) return send(res, 429, { error: 'too_many_attempts', retryAfter: w1 || w2 });
            const fail = async (status, error) => { await recordFail(db, ipTid); await recordFail(db, glTid); return send(res, status, { error }); };

            const adm = await db.doc(`${BASE}/config/admin_settings`).get();
            const cfg = adm.exists ? adm.data() : {};
            if (!cfg.masterHash || !cfg.masterSalt) return send(res, 503, { error: 'not_configured' });
            const authApp = cfg.authAppEnabled !== undefined ? cfg.authAppEnabled === true : true;
            if (authApp && !cfg.totpSecret) return send(res, 503, { error: 'not_configured' });

            const issue = async () => {
                const uid = await adminUid(db);
                if (!uid) return send(res, 503, { error: 'no_admin_uid' });
                const token = await getAuth().createCustomToken(uid, { adminCode: true });
                return send(res, 200, { ok: true, token });
            };

            if (step === 1) {
                if (!authApp) return send(res, 200, { ok: true, skip: true });
                if (!validateTotp(cfg.totpSecret, otp, now())) return fail(401, 'bad_otp');
                return send(res, 200, { ok: true, stage: sign({ s: 1, exp: now() + STAGE_TTL_MS, ip: sha256Hex(ip, 'stage-ip') }) });
            }
            if (step === 2) {
                if (authApp && (readStage(body.stage, ip) || {}).s !== 1) return send(res, 401, { error: 'stage_required' });
                if (!code || !safeEq(sha256Hex(code, cfg.masterSalt), cfg.masterHash)) return fail(401, 'invalid');
                if (!authApp) return issue();
                return send(res, 200, { ok: true, needOtp: true, stage: sign({ s: 2, exp: now() + STAGE_TTL_MS, ip: sha256Hex(ip, 'stage-ip') }) });
            }
            // step 3
            if (!authApp) return send(res, 400, { error: 'bad_request' });
            if ((readStage(body.stage, ip) || {}).s !== 2) return send(res, 401, { error: 'stage_required' });
            if (!validateTotp(cfg.totpSecret, otp, now())) return fail(401, 'bad_otp');
            return issue();
        } catch (e) {
            console.error('admin login api error:', e && e.message);
            return send(res, 500, { error: 'server_error' });
        }
    };
}

let _admin = null;
function admin() {
    if (_admin) return _admin;
    const a = require('firebase-admin');
    if (!a.apps.length) a.initializeApp({ credential: a.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
    _admin = a; return a;
}
module.exports = makeHandler({ getDb: () => admin().firestore(), getAuth: () => admin().auth() });
module.exports.makeHandler = makeHandler;
