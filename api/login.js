'use strict';
/**
 * ERG — بوابة الدخول من جهة الخادم (Vercel Serverless)
 * تتحقق من كود القائد/العضو وتُصدر Custom Token يحمل الدور والمعرّف والشركة.
 * لا يلزم Blaze: Firebase Admin يعمل على خطة Spark.
 *
 * متغيرات البيئة في Vercel:
 *   FIREBASE_SERVICE_ACCOUNT : محتوى ملف JSON الخاص بحساب الخدمة (كاملاً)
 *   APP_ID                   : (اختياري) الافتراضي erg2024
 */
const crypto = require('crypto');
const OTPAuth = require('otpauth');

const APP_ID = process.env.APP_ID || 'erg2024';
const BASE = `artifacts/${APP_ID}/public/data`;
const MAX_FAILS = 10;               // محاولات فاشلة مسموحة
const WINDOW_MS = 15 * 60 * 1000;   // خلال 15 دقيقة

// نفس اشتقاق التطبيق: SHA-256( النص + salt ) بصيغة hex
function sha256Hex(text, salt) {
    return crypto.createHash('sha256').update(String(text) + String(salt), 'utf8').digest('hex');
}

function validateTotp(secret, token) {
    try {
        const totp = new OTPAuth.TOTP({
            secret: OTPAuth.Secret.fromBase32(String(secret).replace(/\s+/g, '').toUpperCase()),
            algorithm: 'SHA1', digits: 6, period: 30
        });
        return totp.validate({ token: String(token || '').trim(), window: 1 }) !== null;
    } catch (e) { return false; }
}

function clientIp(req) {
    const xf = (req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip'])) || '';
    return String(xf).split(',')[0].trim() || 'unknown';
}

function makeHandler({ getDb, getAuth, now = () => Date.now() }) {
    const send = (res, status, body) => {
        res.setHeader('Cache-Control', 'no-store');
        res.status(status).json(body);
    };

    async function isBlocked(db, tid) {
        const snap = await db.doc(`${BASE}/login_attempts/${tid}`).get();
        if (!snap.exists) return 0;
        const d = snap.data();
        if (now() - (d.firstAt || 0) > WINDOW_MS) return 0;
        return (d.count || 0) >= MAX_FAILS ? Math.ceil((WINDOW_MS - (now() - d.firstAt)) / 1000) : 0;
    }
    async function recordFail(db, tid) {
        const ref = db.doc(`${BASE}/login_attempts/${tid}`);
        const snap = await ref.get();
        const d = snap.exists ? snap.data() : null;
        if (!d || now() - (d.firstAt || 0) > WINDOW_MS) await ref.set({ count: 1, firstAt: now() });
        else await ref.set({ count: (d.count || 0) + 1, firstAt: d.firstAt });
    }
    async function clearFails(db, tid) {
        try { await db.doc(`${BASE}/login_attempts/${tid}`).delete(); } catch (e) {}
    }

    return async function handler(req, res) {
        try {
            const db = getDb();

            // فحص سلامة الإعداد (آمن: لا يكشف أي قيمة)
            if (req.method === 'GET') {
                const adm = await db.doc(`${BASE}/config/admin_settings`).get();
                const saltLoaded = !!(adm.exists && adm.data().masterSalt);
                return send(res, saltLoaded ? 200 : 503, { ok: saltLoaded, saltLoaded });
            }
            if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });

            let body = req.body;
            if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
            body = body || {};
            const type = body.type;
            const key = typeof body.key === 'string' ? body.key.trim() : '';
            const deviceId = typeof body.deviceId === 'string' ? body.deviceId.slice(0, 120) : '';
            const otp = body.otp;

            if ((type !== 'leader' && type !== 'member') || !key || key.length > 100 || /[\/\\]/.test(key) || !deviceId) {
                return send(res, 400, { error: 'bad_request' });
            }

            const tid = sha256Hex(clientIp(req) + '|' + type, 'throttle').slice(0, 40);
            const wait = await isBlocked(db, tid);
            if (wait > 0) return send(res, 429, { error: 'too_many_attempts', retryAfter: wait });

            const adm = await db.doc(`${BASE}/config/admin_settings`).get();
            const salt = adm.exists ? adm.data().masterSalt : '';
            if (!salt) return send(res, 503, { error: 'not_configured' });

            const coll = type === 'leader' ? 'subscribers' : 'team_keys';
            const hashed = sha256Hex(key, salt);
            let ref = db.doc(`${BASE}/${coll}/${hashed}`);
            let snap = await ref.get();
            if (!snap.exists) {                       // توافق مع المفاتيح القديمة غير المشفرة
                ref = db.doc(`${BASE}/${coll}/${key}`);
                snap = await ref.get();
            }
            if (!snap.exists) { await recordFail(db, tid); return send(res, 401, { error: 'invalid' }); }

            const d = snap.data();
            const id = snap.id;
            let claims;

            if (type === 'leader') {
                if (!d.isPaid || d.status !== 'active') return send(res, 403, { error: 'inactive' });
                if (d.expiryDate) {
                    const daysLeft = Math.ceil((new Date(d.expiryDate) - new Date(now())) / 86400000);
                    if (daysLeft < 0) return send(res, 403, { error: 'expired' });
                }
                // حساب الشركة الإداري: يتطلب رمز Google Authenticator يُفحص هنا على الخادم
                if (d.isCompanyOwner === true && d.isLeader === false) {
                    if (!d.totpSecret) return send(res, 403, { error: 'no_totp' });
                    if (!otp) return send(res, 200, { needOtp: true });
                    if (!validateTotp(d.totpSecret, otp)) { await recordFail(db, tid); return send(res, 401, { error: 'bad_otp' }); }
                }
                const devices = Array.isArray(d.deviceIds) ? d.deviceIds : (d.deviceId ? [d.deviceId] : []);
                if (!devices.includes(deviceId)) {
                    if (devices.length >= 2) return send(res, 403, { error: 'device_limit' });
                    await ref.update({ deviceIds: [...devices, deviceId] });
                }
                claims = { role: 'leader', docId: id, companyId: d.companyId || id, isOwner: d.isCompanyOwner === true };
            } else {
                if (d.deviceId && d.deviceId !== deviceId) return send(res, 403, { error: 'device_locked' });
                if (!d.deviceId) await ref.update({ deviceId });
                claims = { role: 'member', docId: id, parentKey: d.parentKey || '' };
            }

            await clearFails(db, tid);
            const token = await getAuth().createCustomToken(`${type}_${id}`.slice(0, 128), claims);
            return send(res, 200, { ok: true, token, id, type });
        } catch (e) {
            console.error('login api error:', e && e.message);
            return send(res, 500, { error: 'server_error' });
        }
    };
}

// ---- الإنتاج: تهيئة Firebase Admin عند أول طلب ----
let _admin = null;
function admin() {
    if (_admin) return _admin;
    const a = require('firebase-admin');
    if (!a.apps.length) {
        const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        a.initializeApp({ credential: a.credential.cert(sa) });
    }
    _admin = a;
    return a;
}

module.exports = makeHandler({ getDb: () => admin().firestore(), getAuth: () => admin().auth() });
module.exports.makeHandler = makeHandler;
module.exports.sha256Hex = sha256Hex;
