#!/usr/bin/env node
// kms-license — license manager for the KMS (vendor side). VERSION: 1.3 (2026-10-17)
//   1.3: request and activation files are AES-256 zips named KMS-<TOKEN>.zip,
//        password derived from the name (patch 0025); requests are read only
//        from a .zip; `password FILE` prints the zip password; inspect shows
//        the hardware identifiers.
//   1.2: reads the .zip request made by the server's License page (patch 0022)
//        as well as a raw .kmsreq; shows the customer's contact details and the
//        requested duration from the form.
//   1.1: encrypted request/activation files, ledger, local web page.
//
// Keeps your signing keys, reads the encrypted request files customers send
// (KMS-<TOKEN>.zip), issues activation codes bound to that server (KMS-<TOKEN>.zip)
// and keeps a ledger of every license. An activation code is signed with your
// key and encrypted for that one server, so nobody else can read it.
// Node.js 20+, no other dependency.
//
//   node kms-license.mjs keygen                      create the vendor keys (once)
//   node kms-license.mjs inspect FILE.zip            show what a request contains
//   node kms-license.mjs issue FILE.zip [options]    issue a license (writes KMS-<TOKEN>.zip)
//       --customer "Name"      customer name (default: the current license's, or the organization)
//       --days N | --until YYYY-MM-DD | --until-jalali YYYY/MM/DD
//                              validity (--days extends from the current expiry if it is later)
//       --warn-days N          days of warning before the end (default 30)
//       --note "text"          kept in the license and the ledger
//       --out DIR              folder for the activation zip (default issued/)
//   node kms-license.mjs list                        the ledger
//   node kms-license.mjs show SERIAL                 one license from the ledger
//   node kms-license.mjs password FILE.zip           the zip password of a KMS-<TOKEN>.zip
//   (by hand: printf %s TOKEN | openssl dgst -sha256 -hmac KMS-ZIP-1 | awk '{print $NF}' | cut -c1-32)
//   node kms-license.mjs serve [--port 8765]         local web page (127.0.0.1) for all of this
//
// The data folder is ./kms-license-data, or KMS_LICENSE_HOME, or --home DIR:
//   private.json        your private keys (mode 600): keep it secret and back it up
//   vendor-public.json  copy it into the setup kit: assets/license/vendor-public.json
//   ledger.json         every license issued
//   issued/  requests/  the license and request files

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  pbkdf2Sync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const VERSION = "1.3";
const PRODUCT = "kms-outline";
const LICENSE_TYPE = "kms-license";
const REQUEST_TYPE = "kms-license-request";
const LICENSE_ARMOR = "KMS ACTIVATION";
const REQUEST_ARMOR = "KMS LICENSE REQUEST";
const REQUEST_HKDF_INFO = "kms-license-request-v1";
const LICENSE_HKDF_INFO = "kms-license-v2";
const DAY = 24 * 60 * 60 * 1000;
const TZ = "Asia/Tehran";

// ----------------------------------------------------------------------------
// formats (same as server/license/format.ts in patch 0013)
// ----------------------------------------------------------------------------
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const fromB64u = (text) => Buffer.from(text, "base64url");

function armor(label, body) {
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
function unarmor(label, text) {
  const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(text);
  return m ? m[1].replace(/\s+/g, "") : undefined;
}
const keyFingerprint = (key) =>
  createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");

const rawX25519 = (key) => fromB64u(key.export({ format: "jwk" }).x);
const x25519FromRaw = (x) => createPublicKey({ key: { kty: "OKP", crv: "X25519", x }, format: "jwk" });

function boxSeal(plain, recipient, info) {
  const eph = generateKeyPairSync("x25519");
  const epk = rawX25519(eph.publicKey);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipient });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, rawX25519(recipient)]), info, 32));
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  return b64u(Buffer.from(JSON.stringify({ v: 1, alg: "X25519-HKDF-SHA256-A256GCM", epk: b64u(epk), iv: b64u(iv), ct: b64u(ct) }), "utf8"));
}

function boxOpen(body, recipientPrivate, info) {
  const env = JSON.parse(fromB64u(body).toString("utf8"));
  if (env.v !== 1 || env.alg !== "X25519-HKDF-SHA256-A256GCM") throw new Error("unsupported envelope");
  const epk = fromB64u(env.epk);
  const shared = diffieHellman({ privateKey: recipientPrivate, publicKey: x25519FromRaw(env.epk) });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, rawX25519(createPublicKey(recipientPrivate))]), info, 32));
  const ct = fromB64u(env.ct);
  const d = createDecipheriv("aes-256-gcm", key, fromB64u(env.iv));
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// ----------------------------------------------------------------------------
// password-protected zip (same as server/license/zip.ts of patch 0025)
//   KMS-<TOKEN>.zip, one WinZip AES-256 (AE-2) entry,
//   password = first 32 hex of HMAC-SHA256(key "KMS-ZIP-1", TOKEN)
// ----------------------------------------------------------------------------
const ZIP_SECRET = "KMS-ZIP-1";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const KEY_LEN = { 1: 16, 2: 24, 3: 32 };
function newZipName() {
  let bits = 0, value = 0, token = "";
  for (const b of randomBytes(10)) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { token += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return { token, fileName: `KMS-${token}.zip` };
}
const tokenOf = (name) => { const m = /KMS-([A-Z2-7]{16})/i.exec(name || ""); return m ? m[1].toUpperCase() : null; };
const zipPassword = (token) => createHmac("sha256", ZIP_SECRET).update(token).digest("hex").slice(0, 32);
const passwordFor = (name) => { const t = tokenOf(name); return t ? zipPassword(t) : null; };
function aesCtr(key, data) {
  const ecb = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  ecb.setAutoPadding(false);
  const out = Buffer.alloc(data.length), counter = Buffer.alloc(16);
  for (let off = 0, n = 1; off < data.length; off += 16, n++) {
    counter.fill(0);
    for (let i = 0, v = n; i < 8 && v > 0; i++, v = Math.floor(v / 256)) counter[i] = v & 0xff;
    const ks = ecb.update(counter);
    for (let i = 0; i < Math.min(16, data.length - off); i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}
function deriveKeys(password, salt, strength) {
  const len = KEY_LEN[strength];
  const dk = pbkdf2Sync(Buffer.from(password, "utf8"), salt, 1000, 2 * len + 2, "sha1");
  return { enc: dk.subarray(0, len), mac: dk.subarray(len, 2 * len), check: dk.subarray(2 * len) };
}
function writeEncryptedZip(entryName, data, password) {
  const plain = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  const salt = randomBytes(16);
  const keys = deriveKeys(password, salt, 3);
  const ct = aesCtr(keys.enc, deflateRawSync(plain));
  const auth = createHmac("sha1", keys.mac).update(ct).digest().subarray(0, 10);
  const body = Buffer.concat([salt, keys.check, ct, auth]);
  const name = Buffer.from(entryName, "utf8");
  const extra = Buffer.alloc(11);
  extra.writeUInt16LE(0x9901, 0); extra.writeUInt16LE(7, 2); extra.writeUInt16LE(2, 4);
  extra.write("AE", 6, "latin1"); extra.writeUInt8(3, 8); extra.writeUInt16LE(8, 9);
  const d = new Date();
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const flags = 0x0801;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(51, 4); local.writeUInt16LE(flags, 6);
  local.writeUInt16LE(99, 8); local.writeUInt16LE(time, 10); local.writeUInt16LE(date, 12);
  local.writeUInt32LE(0, 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(plain.length, 22);
  local.writeUInt16LE(name.length, 26); local.writeUInt16LE(extra.length, 28);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(0x033f, 4); central.writeUInt16LE(51, 6);
  central.writeUInt16LE(flags, 8); central.writeUInt16LE(99, 10); central.writeUInt16LE(time, 12);
  central.writeUInt16LE(date, 14); central.writeUInt32LE(0, 16); central.writeUInt32LE(body.length, 20);
  central.writeUInt32LE(plain.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt16LE(extra.length, 30);
  central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + name.length + extra.length, 12);
  end.writeUInt32LE(local.length + name.length + extra.length + body.length, 16);
  return Buffer.concat([local, name, extra, body, central, name, extra, end]);
}
function readZip(zip, password) {
  if (zip.length < 22 || zip.readUInt32LE(0) !== 0x04034b50) throw new Error("not a zip file");
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 65535); i--) if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("damaged zip file (no central directory)");
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error("damaged zip file");
    const flags = zip.readUInt16LE(p + 8);
    let method = zip.readUInt16LE(p + 10);
    const compSize = zip.readUInt32LE(p + 20), nameLen = zip.readUInt16LE(p + 28), extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32), localOffset = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString(flags & 0x0800 ? "utf8" : "latin1");
    const extra = zip.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/")) continue;
    const start = localOffset + 30 + zip.readUInt16LE(localOffset + 26) + zip.readUInt16LE(localOffset + 28);
    let data = zip.subarray(start, start + compSize);
    if (flags & 1) {
      if (method !== 99) throw new Error("this zip uses the old ZipCrypto encryption; use AES-256");
      let strength = 0;
      for (let e = 0; e + 4 <= extra.length; e += 4 + extra.readUInt16LE(e + 2)) {
        if (extra.readUInt16LE(e) === 0x9901) { strength = extra.readUInt8(e + 8); method = extra.readUInt16LE(e + 9); }
      }
      const len = KEY_LEN[strength];
      if (!len) throw new Error("unsupported zip encryption");
      if (password === null) throw new Error("file name must keep its KMS-XXXXXXXXXXXXXXXX part (the password comes from it)");
      const keys = deriveKeys(password, data.subarray(0, len / 2), strength);
      if (!data.subarray(len / 2, len / 2 + 2).equals(keys.check)) throw new Error("wrong zip password: was the file renamed?");
      const ct = data.subarray(len / 2 + 2, data.length - 10);
      const mac = createHmac("sha1", keys.mac).update(ct).digest().subarray(0, 10);
      if (!timingSafeEqual(mac, data.subarray(data.length - 10))) throw new Error("the zip file is damaged or was changed");
      data = aesCtr(keys.enc, ct);
    }
    if (method === 8) data = inflateRawSync(data);
    else if (method !== 0) throw new Error(`unsupported zip compression (${method})`);
    return { name, data: Buffer.from(data) };
  }
  throw new Error("the zip file is empty");
}

/** The armored request inside a request zip (only .zip files are accepted). */
function requestFromZip(bytes, fileName) {
  if (!/\.zip$/i.test(fileName || "")) throw new Error("the request must be the .zip file made by the server's License page");
  const text = readZip(bytes, passwordFor(fileName)).data.toString("utf8");
  if (!text.includes(`-----BEGIN ${REQUEST_ARMOR}-----`)) throw new Error("the zip holds no KMS license request");
  return text;
}

/** The activation code as KMS-<TOKEN>.zip. */
function licenseZip(text) {
  const { token, fileName } = newZipName();
  return { fileName, password: zipPassword(token), zip: writeEncryptedZip("activation.kmslic", text, zipPassword(token)) };
}

const readRequestFile = (file) => requestFromZip(fs.readFileSync(file), path.basename(file));

function openRequest(text, boxPrivate) {
  const body = unarmor(REQUEST_ARMOR, text);
  if (!body) throw new Error("not a KMS license request (.kmsreq)");
  let plain;
  try {
    plain = boxOpen(body, boxPrivate, REQUEST_HKDF_INFO);
  } catch {
    throw new Error("the request cannot be decrypted: it was made for another vendor key or was changed");
  }
  const { inner, sig } = JSON.parse(plain.toString("utf8"));
  const innerBytes = fromB64u(inner);
  const payload = JSON.parse(innerBytes.toString("utf8"));
  const serverPublic = createPublicKey(payload.serverPublicKey);
  if (!verify(null, innerBytes, serverPublic, fromB64u(sig))) throw new Error("the request signature is not valid");
  if (keyFingerprint(serverPublic) !== payload.serverKey) throw new Error("the request's server key does not match");
  if (payload.type !== REQUEST_TYPE || payload.v !== 1) throw new Error("unsupported request type");
  if (payload.product !== PRODUCT) throw new Error(`request for another product: ${payload.product}`);
  if (!payload.serverBoxKey) throw new Error("the request is from an older server version without an encryption key; update the server");
  return payload;
}

/** Sign with the vendor key, then encrypt for the one server that asked. */
function sealLicense(payload, signPrivate, serverBoxKey) {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  const plain = Buffer.from(JSON.stringify({ p: b64u(bytes), s: b64u(sign(null, bytes, signPrivate)) }), "utf8");
  return armor(LICENSE_ARMOR, boxSeal(plain, x25519FromRaw(serverBoxKey), LICENSE_HKDF_INFO));
}

// ----------------------------------------------------------------------------
// Jalali <-> Gregorian (jalaali algorithm)
// ----------------------------------------------------------------------------
const div = (a, b) => ~~(a / b);
const mod = (a, b) => a - ~~(a / b) * b;
function jalCal(jy) {
  const breaks = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178];
  const gy = jy + 621;
  let leapJ = -14, jp = breaks[0], jm, jump = 0, n;
  if (jy < jp || jy >= breaks[breaks.length - 1]) throw new Error(`invalid Jalali year ${jy}`);
  for (let i = 1; i < breaks.length; i += 1) {
    jm = breaks[i]; jump = jm - jp;
    if (jy < jm) break;
    leapJ = leapJ + div(jump, 33) * 8 + div(mod(jump, 33), 4);
    jp = jm;
  }
  n = jy - jp;
  leapJ = leapJ + div(n, 33) * 8 + div(mod(n, 33) + 3, 4);
  if (mod(jump, 33) === 4 && jump - n === 4) leapJ += 1;
  const leapG = div(gy, 4) - div((div(gy, 100) + 1) * 3, 4) - 150;
  return { gy, march: 20 + leapJ - leapG };
}
const g2d = (gy, gm, gd) =>
  div((gy + div(gm - 8, 6) + 100100) * 1461, 4) + div(153 * mod(gm + 9, 12) + 2, 5) + gd - 34840408 -
  div(div(gy + 100100 + div(gm - 8, 6), 100) * 3, 4) + 752;
function d2g(jdn) {
  let j = 4 * jdn + 139361631;
  j = j + div(div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908;
  const i = div(mod(j, 1461), 4) * 5 + 308;
  const gd = div(mod(i, 153), 5) + 1;
  const gm = mod(div(i, 153), 12) + 1;
  return { gy: div(j, 1461) - 100100 + div(8 - gm, 6), gm, gd };
}
function jalaliToGregorian(jy, jm, jd) {
  if (jm < 1 || jm > 12 || jd < 1 || jd > 31 || (jm > 6 && jd > 30)) throw new Error("invalid Jalali date");
  const r = jalCal(jy);
  return d2g(g2d(r.gy, 3, r.march) + (jm - 1) * 31 - div(jm, 7) * (jm - 7) + jd - 1);
}
const faDigits = (s) => String(s).replace(/[۰-۹]/g, (c) => c.charCodeAt(0) - 0x6f0).replace(/[٠-٩]/g, (c) => c.charCodeAt(0) - 0x660);
const pad = (n) => String(n).padStart(2, "0");

/** End of a Gregorian day in Tehran time. */
const endOfDay = ({ gy, gm, gd }) => new Date(`${gy}-${pad(gm)}-${pad(gd)}T23:59:59+03:30`);

function parseUntilJalali(text) {
  const m = /^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$/.exec(faDigits(text).trim());
  if (!m) throw new Error("Jalali date must look like 1406/12/29");
  return endOfDay(jalaliToGregorian(+m[1], +m[2], +m[3]));
}
function parseUntil(text) {
  const m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(faDigits(text).trim());
  if (!m) throw new Error("date must look like 2027-03-20");
  return endOfDay({ gy: +m[1], gm: +m[2], gd: +m[3] });
}
const fmtJalali = (iso) =>
  iso ? new Intl.DateTimeFormat("fa-IR-u-ca-persian", { dateStyle: "long", timeZone: TZ }).format(new Date(iso)) : "—";
const fmtJalaliNum = (iso) => {
  if (!iso) return "—";
  const parts = new Intl.DateTimeFormat("en-US-u-ca-persian", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: TZ }).formatToParts(new Date(iso));
  const get = (t) => parts.find((p) => p.type === t)?.value.replace(/\D/g, "");
  return `${get("year")}/${get("month")}/${get("day")}`;
};

// ----------------------------------------------------------------------------
// vendor data folder
// ----------------------------------------------------------------------------
function homeDir(args) {
  return path.resolve(args.home || process.env.KMS_LICENSE_HOME || "kms-license-data");
}
const P = (home) => ({
  priv: path.join(home, "private.json"),
  pub: path.join(home, "vendor-public.json"),
  ledger: path.join(home, "ledger.json"),
  issued: path.join(home, "issued"),
  requests: path.join(home, "requests"),
});

function keygen(home, force) {
  const p = P(home);
  if (fs.existsSync(p.priv) && !force) throw new Error(`keys already exist in ${home} (never replace them: issued licenses depend on them)`);
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const s = generateKeyPairSync("ed25519");
  const b = generateKeyPairSync("x25519");
  const created = new Date().toISOString();
  const priv = { VERSION: `kms-license ${VERSION}`, v: 1, product: PRODUCT, created, sign: s.privateKey.export({ format: "jwk" }), box: b.privateKey.export({ format: "jwk" }) };
  const pub = { VERSION: `kms-license ${VERSION}`, v: 1, product: PRODUCT, created, sign: s.publicKey.export({ format: "jwk" }), box: b.publicKey.export({ format: "jwk" }) };
  fs.writeFileSync(p.priv, JSON.stringify(priv, null, 2) + "\n", { mode: 0o600 });
  fs.writeFileSync(p.pub, JSON.stringify(pub, null, 2) + "\n", { mode: 0o644 });
  return p;
}

function loadKeys(home) {
  const p = P(home);
  if (!fs.existsSync(p.priv)) throw new Error(`no keys in ${home}; run: node kms-license.mjs keygen`);
  const priv = JSON.parse(fs.readFileSync(p.priv, "utf8"));
  return {
    signPrivate: createPrivateKey({ key: priv.sign, format: "jwk" }),
    signPublic: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: priv.sign.x }, format: "jwk" }),
    boxPrivate: createPrivateKey({ key: priv.box, format: "jwk" }),
  };
}

const readLedger = (home) => {
  try { return JSON.parse(fs.readFileSync(P(home).ledger, "utf8")); } catch { return { VERSION: `kms-license ${VERSION}`, licenses: [] }; }
};
function writeLedger(home, ledger) {
  const file = P(home).ledger;
  if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.bak`);
  fs.writeFileSync(file + ".tmp", JSON.stringify(ledger, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(file + ".tmp", file);
}

function summarizeRequest(req, ledger) {
  const previous = ledger.licenses.filter((l) => l.installId === req.installId);
  const contact = req.contact || {};
  const requested = req.requested || {};
  return {
    organization: req.organization || "",
    admin: req.admin || {},
    contact,
    requested,
    createdAt: req.createdAt,
    installId: req.installId,
    serverKey: req.serverKey,
    hardware: Object.keys(req.hw || {}),
    hw: req.hw || {},
    current: req.current || null,
    appVersion: req.appVersion || "",
    knownServer: previous.length > 0,
    previous: previous.map((l) => ({ serial: l.serial, customer: l.customer, expiresAt: l.expiresAt })),
    suggestedCustomer:
      req.current?.customer || previous.at(-1)?.customer || contact.legalName || req.organization || "",
    suggestedDays: Number.isFinite(requested.days) ? requested.days : "",
  };
}

function issue(home, requestText, opts) {
  const keys = loadKeys(home);
  const req = openRequest(requestText, keys.boxPrivate);
  const ledger = readLedger(home);
  const info = summarizeRequest(req, ledger);
  const now = new Date();
  const customer = (opts.customer || info.suggestedCustomer || "").trim();
  if (!customer) throw new Error("--customer is required (the request has no organization name)");
  let expires;
  if (opts.untilJalali) expires = parseUntilJalali(opts.untilJalali);
  else if (opts.until) expires = parseUntil(opts.until);
  else if (opts.days) {
    const days = Number(faDigits(opts.days));
    if (!Number.isFinite(days) || days < 1 || days > 3660) throw new Error("--days must be 1..3660");
    // A renewal continues from the current expiry when that is later than now.
    const current = req.current?.expiresAt ? Date.parse(req.current.expiresAt) : 0;
    const base = Math.max(now.getTime(), current || 0);
    expires = new Date(base + days * DAY);
  } else throw new Error("give --days N, --until YYYY-MM-DD or --until-jalali YYYY/MM/DD");
  if (expires.getTime() <= now.getTime()) throw new Error("the end date is in the past");
  const seq = ledger.licenses.length + 1;
  const serial = opts.serial || `KMS-${now.getFullYear()}-${String(seq).padStart(4, "0")}`;
  if (ledger.licenses.some((l) => l.serial === serial)) throw new Error(`serial ${serial} exists already`);
  const warnDays = opts.warnDays !== undefined ? Number(faDigits(opts.warnDays)) : 30;
  const payload = {
    type: LICENSE_TYPE,
    v: 1,
    product: PRODUCT,
    serial,
    customer,
    installId: req.installId,
    serverKey: req.serverKey,
    hw: req.hw,
    issuedAt: now.toISOString(),
    notBefore: new Date(now.getTime() - 5 * 60 * 1000).toISOString(),
    expiresAt: expires.toISOString(),
    warnDays,
    ...(opts.note ? { note: String(opts.note) } : {}),
  };
  const text = sealLicense(payload, keys.signPrivate, req.serverBoxKey);
  const p = P(home);
  fs.mkdirSync(p.issued, { recursive: true });
  fs.mkdirSync(p.requests, { recursive: true });
  const licenseFile = path.join(p.issued, `${serial}.kmslic`);
  fs.writeFileSync(licenseFile, text);
  // 1.3: what goes to the customer is the password-protected KMS-<TOKEN>.zip.
  const z = licenseZip(text);
  const outDir = opts.out ? path.resolve(String(opts.out)) : p.issued;
  fs.mkdirSync(outDir, { recursive: true });
  const zipFile = path.join(outDir, z.fileName);
  fs.writeFileSync(zipFile, z.zip);
  const requestFile = path.join(p.requests, `${serial}.kmsreq`);
  fs.writeFileSync(requestFile, requestText.trim() + "\n");
  const record = {
    serial, customer, organization: req.organization || "", adminEmail: req.admin?.email || "",
    installId: req.installId, serverKey: req.serverKey, serverBoxKey: req.serverBoxKey, hw: req.hw,
    issuedAt: payload.issuedAt, notBefore: payload.notBefore, expiresAt: payload.expiresAt, warnDays,
    note: opts.note || "", renewalOf: req.current?.serial || "",
    licenseFile: path.relative(home, licenseFile), requestFile: path.relative(home, requestFile),
    zipFile: path.relative(home, zipFile),
    contact: req.contact || null, requested: req.requested || null,
  };
  ledger.licenses.push(record);
  writeLedger(home, ledger);
  return { text, record, licenseFile, zipFile, zip: z.zip, fileName: z.fileName, password: z.password };
}

// ----------------------------------------------------------------------------
// local web page
// ----------------------------------------------------------------------------
function page(token) {
  return `<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>مدیریت مجوزهای KMS</title>
<!-- kms-license ${VERSION} -->
<style>
:root{--bg:#f6f4ef;--card:#fffdf8;--text:#1b1f2a;--muted:#6b6f7a;--line:#e6e1d6;--accent:#0f8c8c;--danger:#c0392b;--warn:#c98a1b}
@media (prefers-color-scheme:dark){:root{--bg:#121826;--card:#1a2133;--text:#e8e6e1;--muted:#9aa3b5;--line:#2c3650;--accent:#3cc7c0;--danger:#e06666;--warn:#e3b341}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.8 Vazirmatn,"Vazirmatn FD",Tahoma,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:20px}h2{font-size:17px;margin:0 0 8px}
main{max-width:1100px;margin:0 auto;padding:16px;display:grid;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
textarea,input{width:100%;font:inherit;color:inherit;background:transparent;border:1px solid var(--line);border-radius:6px;padding:6px 8px}
textarea{direction:ltr;font-family:ui-monospace,monospace;font-size:12px;min-height:110px}
label{display:block;margin:8px 0 2px;color:var(--muted);font-size:13px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px 16px}
button{font:inherit;border:0;border-radius:6px;padding:6px 14px;background:var(--accent);color:#fff;cursor:pointer}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px}.kv b{font-weight:500;color:var(--muted)}
.ltr{direction:ltr;unicode-bidi:isolate;font-family:ui-monospace,monospace;font-size:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:start;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:13px}.ok{color:var(--accent)}.warn{color:var(--warn)}.bad{color:var(--danger)}
.err{color:var(--danger);white-space:pre-wrap}.presets button{margin-inline-end:6px}.hidden{display:none}
</style></head><body>
<header><h1>مدیریت مجوزهای KMS</h1><div style="color:var(--muted);font-size:13px">kms-license ${VERSION} · فقط روی همین رایانه در دسترس است</div></header>
<main>
<section class="card"><h2>۱. فایل درخواست مشتری</h2>
<label>فایل ‎KMS-….zip‎ مشتری را انتخاب کنید (نام فایل را تغییر ندهید؛ رمز zip از روی نام ساخته می‌شود)</label>
<input type="file" id="file" accept=".zip,application/zip"><div id="reqErr" class="err"></div>
<div id="reqInfo" class="hidden" style="margin-top:12px"></div></section>
<section class="card hidden" id="issueCard"><h2>۲. صدور کد فعال‌سازی</h2>
<div class="row"><div><label>نام مشتری</label><input id="customer"></div>
<div><label>اعتبار تا تاریخ (شمسی، مثل ۱۴۰۶/۱۲/۲۹)</label><input id="untilJ"></div>
<div><label>یا مدت (روز)</label><input id="days" inputmode="numeric"></div>
<div><label>روزهای هشدار پیش از پایان</label><input id="warn" value="30" inputmode="numeric"></div></div>
<div class="presets" style="margin-top:8px"><button class="ghost" data-d="90">۳ ماه</button><button class="ghost" data-d="180">۶ ماه</button><button class="ghost" data-d="365">۱ سال</button><button class="ghost" data-d="730">۲ سال</button></div>
<label>یادداشت (اختیاری)</label><input id="note">
<div style="margin-top:12px"><button id="issue">صدور و دریافت فایل فعال‌سازی</button></div><div id="issueErr" class="err"></div>
<div id="issued" class="hidden" style="margin-top:12px"><div id="issuedMsg"></div>
<div style="margin-top:6px"><button id="dl">دریافت دوباره فایل فعال‌سازی ‎.zip‎</button></div></div></section>
<section class="card"><h2>مجوزهای صادرشده</h2><div style="overflow-x:auto"><table><thead><tr><th>سریال</th><th>مشتری</th><th>سازمان</th><th>شناسه نصب</th><th>صدور</th><th>اعتبار تا</th><th>وضعیت</th><th></th></tr></thead><tbody id="ledger"></tbody></table></div></section>
</main>
<script>
const T=${JSON.stringify(token)};const $=(id)=>document.getElementById(id);
const fa=(n)=>new Intl.NumberFormat("fa-IR").format(n);
const jd=(iso)=>iso?new Intl.DateTimeFormat("fa-IR-u-ca-persian",{dateStyle:"long",timeZone:"${TZ}"}).format(new Date(iso)):"—";
async function api(p,body){const r=await fetch(p,{method:body?"POST":"GET",headers:{"Content-Type":"application/json","X-Token":T},body:body?JSON.stringify(body):undefined});const j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j;}
function esc(s){return String(s??"").replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function status(l){const d=Math.ceil((Date.parse(l.expiresAt)-Date.now())/864e5);if(d<=0)return '<span class="bad">منقضی</span>';if(d<=(l.warnDays||30))return '<span class="warn">'+fa(d)+' روز مانده</span>';return '<span class="ok">فعال · '+fa(d)+' روز</span>';}
async function loadLedger(){const {licenses}=await api("/api/ledger");$("ledger").innerHTML=licenses.slice().reverse().map(l=>'<tr><td class="ltr">'+esc(l.serial)+'</td><td>'+esc(l.customer)+'</td><td>'+esc(l.organization)+'</td><td class="ltr">'+esc(l.installId.slice(0,12))+'…</td><td>'+jd(l.issuedAt)+'</td><td>'+jd(l.expiresAt)+'</td><td>'+status(l)+'</td><td><button class="ghost" data-s="'+esc(l.serial)+'">فایل</button></td></tr>').join("")||'<tr><td colspan="8" style="color:var(--muted)">هنوز مجوزی صادر نشده است.</td></tr>';}
$("ledger").addEventListener("click",async(e)=>{const s=e.target.dataset?.s;if(!s)return;const r=await api("/api/license?serial="+encodeURIComponent(s));saveZip(r.zip,r.fileName);});
function saveZip(b64,name){const bin=atob(b64);const b=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([b],{type:"application/zip"}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);}
let reqFile=null;
$("file").addEventListener("change",async(e)=>{const f=e.target.files[0];e.target.value="";if(!f)return;const b=new Uint8Array(await f.arrayBuffer());let s="";for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);reqFile={zip:btoa(s),fileName:f.name};inspect();});
async function inspect(){$("reqErr").textContent="";$("reqInfo").classList.add("hidden");$("issueCard").classList.add("hidden");$("issued").classList.add("hidden");
 try{if(!/\\.zip$/i.test(reqFile.fileName))throw new Error("فقط فایل zip درخواست پذیرفته می‌شود");const i=await api("/api/inspect",reqFile);
 const rep=[i.contact?.firstName,i.contact?.lastName].filter(Boolean).join(" ");
 const wants=i.requested?.days?fa(i.requested.days)+' روز':'—';
 $("reqInfo").innerHTML='<div class="kv"><b>دارندهٔ مجوز</b><span>'+esc(i.contact?.legalName||"—")+'</span><b>نماینده</b><span>'+esc([rep,i.contact?.phone].filter(Boolean).join(" · ")||"—")+'</span><b>مدت درخواستی</b><span>'+wants+(i.requested?.note?' — '+esc(i.requested.note):'')+'</span><b>سازمان</b><span>'+esc(i.organization||"—")+'</span><b>مدیر</b><span>'+esc([i.admin.name,i.admin.email].filter(Boolean).join(" · ")||"—")+'</span><b>تاریخ درخواست</b><span>'+jd(i.createdAt)+'</span><b>شناسه نصب</b><span class="ltr">'+esc(i.installId)+'</span><b>شناسه‌های سخت‌افزار</b><span>'+fa(i.hardware.length)+'<div class="ltr">'+Object.entries(i.hw||{}).map(([k,v])=>esc(k)+': '+esc(v)).join("<br>")+'</div></span><b>مجوز فعلی</b><span>'+(i.current?esc(i.current.serial)+' · '+esc(i.current.customer)+' · تا '+jd(i.current.expiresAt):"ندارد (فعال‌سازی اول)")+'</span><b>سرور</b><span>'+(i.knownServer?"شناخته‌شده: "+fa(i.previous.length)+" مجوز قبلی":"سرور جدید")+'</span></div>';
 $("reqInfo").classList.remove("hidden");$("customer").value=i.suggestedCustomer;$("days").value=i.suggestedDays||"";$("untilJ").value="";$("note").value=i.requested?.note||"";$("issueCard").classList.remove("hidden");}catch(err){$("reqErr").textContent=err.message;}}
document.querySelectorAll(".presets button").forEach(b=>b.addEventListener("click",()=>{$("days").value=b.dataset.d;$("untilJ").value="";}));
let last;$("issue").addEventListener("click",async()=>{$("issueErr").textContent="";
 try{const r=await api("/api/issue",{...reqFile,customer:$("customer").value,untilJalali:$("untilJ").value||undefined,days:$("untilJ").value?undefined:($("days").value||undefined),warnDays:$("warn").value,note:$("note").value||undefined});
 last=r;$("issuedMsg").innerHTML='مجوز <span class="ltr">'+esc(r.record.serial)+'</span> برای «'+esc(r.record.customer)+'» تا '+jd(r.record.expiresAt)+' صادر شد. فایل <span class="ltr">'+esc(r.fileName)+'</span> را برای مشتری بفرستید (رمز zip: <span class="ltr">'+esc(r.password)+'</span>).';$("issued").classList.remove("hidden");saveZip(r.zip,r.fileName);loadLedger();}catch(err){$("issueErr").textContent=err.message;}});
$("dl").addEventListener("click",()=>last&&saveZip(last.zip,last.fileName));
loadLedger();
</script></body></html>`;
}

function serve(home, port, host) {
  loadKeys(home);
  const token = randomBytes(16).toString("hex");
  const send = (res, code, body, type = "application/json; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, page(token), "text/html; charset=utf-8");
    if (req.headers["x-token"] !== token) return send(res, 403, { error: "forbidden" });
    let raw = "";
    req.on("data", (c) => { raw += c; if (raw.length > 2e6) req.destroy(); });
    req.on("end", () => {
      try {
        const body = raw ? JSON.parse(raw) : {};
        if (url.pathname === "/api/ledger") return send(res, 200, readLedger(home));
        const requestText = () => requestFromZip(Buffer.from(String(body.zip || ""), "base64"), body.fileName);
        if (url.pathname === "/api/inspect") {
          const keys = loadKeys(home);
          return send(res, 200, summarizeRequest(openRequest(requestText(), keys.boxPrivate), readLedger(home)));
        }
        if (url.pathname === "/api/issue" && req.method === "POST") {
          const r = issue(home, requestText(), { ...body, out: undefined });
          return send(res, 200, { record: r.record, fileName: r.fileName, zip: r.zip.toString("base64"), password: r.password });
        }
        if (url.pathname === "/api/license") {
          const rec = readLedger(home).licenses.find((l) => l.serial === url.searchParams.get("serial"));
          if (!rec) return send(res, 404, { error: "not found" });
          const z = licenseZip(fs.readFileSync(path.join(home, rec.licenseFile), "utf8"));
          return send(res, 200, { fileName: z.fileName, zip: z.zip.toString("base64"), password: z.password });
        }
        send(res, 404, { error: "not found" });
      } catch (err) {
        send(res, 400, { error: err.message });
      }
    });
  });
  server.listen(port, host, () => {
    console.log(`kms-license ${VERSION}: http://${host}:${port}/  (data: ${home}; Ctrl+C to stop)`);
  });
}

// ----------------------------------------------------------------------------
// command line
// ----------------------------------------------------------------------------
function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      const key = k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (v !== undefined) args[key] = v;
      else if (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) args[key] = argv[++i];
      else args[key] = true;
    } else args._.push(a);
  }
  return args;
}

function printLicense(rec) {
  console.log(`  serial:    ${rec.serial}`);
  console.log(`  customer:  ${rec.customer}`);
  console.log(`  install:   ${rec.installId}`);
  console.log(`  valid:     ${fmtJalaliNum(rec.notBefore)} .. ${fmtJalaliNum(rec.expiresAt)}  (${rec.expiresAt.slice(0, 10)})`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args.version ? "version" : args._[0];
  const home = homeDir(args);
  try {
    switch (cmd) {
      case "keygen": {
        const p = keygen(home, args.force === true);
        console.log(`Keys created in ${home}`);
        console.log(`  private (keep secret, back it up): ${p.priv}`);
        console.log(`  public  (copy into the kit as assets/license/vendor-public.json): ${p.pub}`);
        break;
      }
      case "inspect": {
        const keys = loadKeys(home);
        const req = openRequest(readRequestFile(args._[1]), keys.boxPrivate);
        const s = summarizeRequest(req, readLedger(home));
        const rep = [s.contact.firstName, s.contact.lastName].filter(Boolean).join(" ");
        console.log(`  organization: ${s.organization || "-"}`);
        console.log(`  license for:  ${s.contact.legalName || "-"}`);
        console.log(`  representative: ${[rep, s.contact.phone].filter(Boolean).join(" · ") || "-"}`);
        console.log(`  wants:        ${s.requested.days ? `${s.requested.days} day(s)` : "-"}${s.requested.note ? ` — ${s.requested.note}` : ""}`);
        console.log(`  admin:        ${[s.admin.name, s.admin.email].filter(Boolean).join(" <") + (s.admin.email ? ">" : "") || "-"}`);
        console.log(`  requested at: ${fmtJalaliNum(s.createdAt)} (${s.createdAt})`);
        console.log(`  install ID:   ${s.installId}`);
        console.log(`  hardware:     ${s.hardware.length} identifiers`);
        for (const [k, v] of Object.entries(s.hw)) console.log(`    ${k.padEnd(10)} ${String(v)}`);
        console.log(`  current:      ${s.current ? `${s.current.serial} ${s.current.customer} until ${fmtJalaliNum(s.current.expiresAt)}` : "none (first activation)"}`);
        console.log(`  known server: ${s.knownServer ? `yes, ${s.previous.length} earlier license(s)` : "no"}`);
        break;
      }
      case "issue": {
        if (!args._[1]) throw new Error("usage: issue FILE.zip --days N | --until-jalali YYYY/MM/DD");
        const r = issue(home, readRequestFile(args._[1]), args);
        console.log(`Send to the customer: ${r.zipFile}`);
        console.log(`  zip password: ${r.password}  (ledger copy: ${r.licenseFile})`);
        printLicense(r.record);
        break;
      }
      case "list": {
        const { licenses } = readLedger(home);
        if (!licenses.length) console.log("No licenses issued yet.");
        for (const l of licenses) {
          const days = Math.ceil((Date.parse(l.expiresAt) - Date.now()) / DAY);
          console.log(`${l.serial}\t${fmtJalaliNum(l.expiresAt)}\t${days > 0 ? `${days}d left` : "expired"}\t${l.customer}\t${l.installId.slice(0, 12)}`);
        }
        break;
      }
      case "show": {
        const rec = readLedger(home).licenses.find((l) => l.serial === args._[1]);
        if (!rec) throw new Error(`no license ${args._[1]} in the ledger`);
        printLicense(rec);
        console.log(`  file:      ${path.join(home, rec.licenseFile)}`);
        if (rec.note) console.log(`  note:      ${rec.note}`);
        break;
      }
      case "password": {
        const name = path.basename(String(args._[1] || ""));
        const token = tokenOf(name);
        if (!token) throw new Error("usage: password KMS-XXXXXXXXXXXXXXXX.zip");
        console.log(zipPassword(token));
        break;
      }
      case "serve":
        serve(home, Number(args.port || 8765), "127.0.0.1");
        break;
      case "version":
      case "--version":
        console.log(`kms-license ${VERSION}`);
        break;
      default: {
        const own = fs.readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(1, 26);
        console.log(own.map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
        if (cmd && cmd !== "help") process.exitCode = 2;
      }
    }
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exitCode = 1;
  }
}

main();
