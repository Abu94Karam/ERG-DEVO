'use strict';
/**
 * ERG — بوابة الدخول v2 (Vercel Serverless) — دخول بالرمز التعريفي للشركة
 *
 * التدفق: (الرمز التعريفي للشركة) + (قائد/عضو) + (الكود)
 *  - الرمز التعريفي يحدّد «مساحة الأسماء» (nsId) فيمكن تكرار نفس الكود بين شركتين.
 *  - معرّف وثيقة القائد/العضو = SHA-256( nsId | الكود + salt )  → فريد داخل كل شركة.
 *  - الرموز التعريفية تُحفظ في المجموعة المحمية company_secrets/{nsId} { accessCode }
 *    (لا تُقرأ إلا بالإدارة العليا ومالك الشركة عبر القواعد، والخادم يقرؤها عبر Admin SDK).
 *
 * متغيرات البيئة في Vercel (كما هي، بلا جديد):
 *   FIREBASE_SERVICE_ACCOUNT , APP_ID (اختياري)
 *
 * يُنشر باسم api/login-v2.js بجانب api/login.js القديم دون أي تعارض.
 */
const crypto = require('crypto');
const OTPAuth = require('otpauth');

const APP_ID = process.env.APP_ID || 'erg2024';
const BASE = `artifacts/${APP_ID}/public/data`;
const WINDOW_MS = 15 * 60 * 1000;   // نافذة العدّ
const MAX_FAILS_IP = 10;            // محاولات فاشلة لكل IP ونوع
const MAX_FAILS_COMPANY = 40;       // محاولات فاشلة لكل شركة ونوع (يقاوم التخمين الموزّع)

function sha256Hex(text, salt) {
    return crypto.createHash('sha256').update(String(text) + String(salt), 'utf8').digest('hex');
}
// نفس صيغة توليد معرّف الوثيقة في التطبيق: hashInput(nsId + '|' + key, MASTER_SALT)
function docIdFor(nsId, key, salt) { return sha256Hex(nsId + '|' + key, salt); }
// الرمز التعريفي: أحرف كبيرة وأرقام فقط (تُهمل الشرطات والمسافات)
function normCompanyCode(s) { return String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }

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

    // ---- عدّادات المحاولات الفاشلة (ذرّية عبر transaction) ----
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
            const snap = await tx.get(ref);
            const d = snap.exists ? snap.data() : null;
            const t = now();
            if (!d || t - (d.firstAt || 0) > WINDOW_MS) tx.set(ref, { count: 1, firstAt: t });
            else tx.set(ref, { count: (d.count || 0) + 1, firstAt: d.firstAt });
        });
    }
    async function clearFails(db, tid) {
        try { await db.doc(`${BASE}/login_attempts/${tid}`).delete(); } catch (e) {}
    }
    // نفس الرد لأي خطأ هوية (شركة غير موجودة أو كود خاطئ) كي لا يُكشف أيّهما
    const invalid = (res) => send(res, 401, { error: 'invalid' });

    function checkSubscription(d) {
        if (!d.isPaid || d.status !== 'active') return 'inactive';
        if (d.expiryDate) {
            const daysLeft = Math.ceil((new Date(d.expiryDate) - new Date(now())) / 86400000);
            if (daysLeft < 0) return 'expired';
        }
        return null;
    }

    return async function handler(req, res) {
        try {
            const db = getDb();

            // فحص سلامة الإعداد (لا يكشف أي قيمة)
            if (req.method === 'GET') {
                const adm = await db.doc(`${BASE}/config/admin_settings`).get();
                const saltLoaded = !!(adm.exists && adm.data().masterSalt);
                return send(res, saltLoaded ? 200 : 503, { ok: saltLoaded, saltLoaded, version: 2 });
            }
            if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });

            let body = req.body;
            if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
            body = body || {};
            const type = body.type;
            const companyCode = normCompanyCode(body.companyCode);
            const key = typeof body.key === 'string' ? body.key.trim() : '';
            const deviceId = typeof body.deviceId === 'string' ? body.deviceId.slice(0, 120) : '';
            const otp = body.otp;

            if ((type !== 'leader' && type !== 'member')
                || companyCode.length < 6 || companyCode.length > 40
                || !key || key.length > 100 || /[\u0000-\u001f]/.test(key)
                || !deviceId) {
                return send(res, 400, { error: 'bad_request' });
            }

            // 1) سقف المحاولات لكل IP
            const ipTid = sha256Hex(clientIp(req) + '|' + type, 'throttle').slice(0, 40);
            const waitIp = await blockedFor(db, ipTid, MAX_FAILS_IP);
            if (waitIp > 0) return send(res, 429, { error: 'too_many_attempts', retryAfter: waitIp });

            const adm = await db.doc(`${BASE}/config/admin_settings`).get();
            const salt = adm.exists ? adm.data().masterSalt : '';
            if (!salt) return send(res, 503, { error: 'not_configured' });

            // 2) تحديد الشركة من الرمز التعريفي
            const cq = await db.collection(`${BASE}/company_secrets`).where('accessCode', '==', companyCode).limit(1).get();
            if (cq.empty) { await recordFail(db, ipTid); return invalid(res); }
            const nsId = cq.docs[0].id;

            // 3) سقف المحاولات لكل شركة (مهما تعددت العناوين)
            const coTid = sha256Hex('co|' + nsId + '|' + type, 'throttle').slice(0, 40);
            const waitCo = await blockedFor(db, coTid, MAX_FAILS_COMPANY);
            if (waitCo > 0) return send(res, 429, { error: 'too_many_attempts', retryAfter: waitCo });

            // 4) الوثيقة داخل مساحة الشركة فقط
            const coll = type === 'leader' ? 'subscribers' : 'team_keys';
            const id = docIdFor(nsId, key, salt);
            const ref = db.doc(`${BASE}/${coll}/${id}`);
            const snap = await ref.get();
            if (!snap.exists || (snap.data().nsId || '') !== nsId) {
                await recordFail(db, ipTid); await recordFail(db, coTid);
                return invalid(res);
            }

            const d = snap.data();
            let claims;

            if (type === 'leader') {
                const bad = checkSubscription(d);
                if (bad) return send(res, 403, { error: bad });
                // حساب الشركة الإداري: رمز Google Authenticator يُفحص هنا
                if (d.isCompanyOwner === true && d.isLeader === false) {
                    if (!d.totpSecret) return send(res, 403, { error: 'no_totp' });
                    if (!otp) return send(res, 200, { needOtp: true });
                    if (!validateTotp(d.totpSecret, otp)) {
                        await recordFail(db, ipTid); await recordFail(db, coTid);
                        return send(res, 401, { error: 'bad_otp' });
                    }
                }
                const devices = Array.isArray(d.deviceIds) ? d.deviceIds : (d.deviceId ? [d.deviceId] : []);
                if (!devices.includes(deviceId)) {
                    if (devices.length >= 2) return send(res, 403, { error: 'device_limit' });
                    await ref.update({ deviceIds: [...devices, deviceId] });
                }
                claims = { role: 'leader', docId: id, nsId, companyId: d.companyId || id, isOwner: d.isCompanyOwner === true };
            } else {
                // العضو يتبع اشتراك قائده: يجب أن يكون نشطاً وغير منتهٍ وضمن نفس الشركة
                const pRef = db.doc(`${BASE}/subscribers/${d.parentKey || '_'}`);
                const pSnap = d.parentKey ? await pRef.get() : null;
                if (!pSnap || !pSnap.exists || (pSnap.data().nsId || '') !== nsId) return send(res, 403, { error: 'inactive' });
                const bad = checkSubscription(pSnap.data());
                if (bad) return send(res, 403, { error: bad });
                if (d.deviceId && d.deviceId !== deviceId) return send(res, 403, { error: 'device_locked' });
                if (!d.deviceId) await ref.update({ deviceId });
                claims = { role: 'member', docId: id, nsId, parentKey: d.parentKey, companyId: pSnap.data().companyId || d.parentKey };
            }

            await clearFails(db, ipTid);   // عدّاد الشركة لا يُصفَّر بالنجاح عمداً
            const token = await getAuth().createCustomToken(`${type}_${id}`.slice(0, 128), claims);
            return send(res, 200, { ok: true, token, id, type });
        } catch (e) {
            console.error('login v2 api error:', e && e.message);
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
module.exports.docIdFor = docIdFor;
module.exports.normCompanyCode = normCompanyCode;
