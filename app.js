'use strict';
/*
 * DUALTRON / Minimotors Tuning - Web Bluetooth. Implements the BLE protocol proven from
 * com.minimotors.escooter (FastBLE). Proven (app_side, code-verified): GATT service 0xFE60 with write
 * char 0xFE61 + notify char 0xFE62; the fixed 16-byte frame (0xAA | seed=Random(0..9) | opcode |
 * 11 payload bytes each stored as value+mask | checksum=sum(bytes[1..13])&0xFF | 0xEE); the reversible
 * payload obfuscation mask = (((seed+33)*73) ^ 169) & 249 carried in cleartext; read opcodes 0x00 telemetry,
 * 0x01 system, 0x02 user, 0x05 controller/max-speed page; write opcodes 0x81 system (legal speed cap
 * byte0 bits6-7, max gear byte5 bits5-7, CCS byte4 bit6, PAS byte4 bit7, motor-protect temp byte10) and
 * 0x82 user (per-field selector writes: top-speed, start-mode, torque, brake, soft-start, km/mi, ABS, ECO,
 * cruise, screen light, auto-off, hazard - each sets a selector byte plus one data byte, the rest echoed).
 * No real BLE auth: the seed is in the packet, so any client that knows the frame can read + write.
 * Device_side UNKNOWN (needs on-device/HCI test): whether firmware honours writes without an owner/password
 * token, whether a cap of OFF really lifts the limit, and the RGB light-strip commands (not reproduced here).
 * An echo only means "accepted"; only the re-read of the live telemetry/settings proves a write took effect.
 */

// Pre-commit cache-buster auto-bumps BUILD and every ?v= on any web-asset change.
const BUILD = 'v8';

// =========================================================================================
//  VERIFIED PROTOCOL CORE (code-proven from com.minimotors.escooter; self-test below runs at load)
// =========================================================================================
// --------------------------- UUIDs (BlueService.java:32-42; Web Bluetooth wants lowercase) ---------------------------
const U = {
  SERVICE: '0000fe60-0000-1000-8000-00805f9b34fb',  // SERVICE_UUID (also the 16-bit scan filter 0xFE60)
  WRITE:   '0000fe61-0000-1000-8000-00805f9b34fb',   // CHARACTERISTIC_WRITE_UUID (wirteData)
  NOTIFY:  '0000fe62-0000-1000-8000-00805f9b34fb'    // CHARACTERISTIC_NOTIFY_UUID (onCharacteristicChanged)
};
const CANDIDATE_SERVICES = [U.SERVICE];   // one unified profile for every Minimotors/Dualtron model

// --------------------------- helpers ---------------------------
const $ = (id) => document.getElementById(id);
const hex = (arr) => Array.from(arr, b => (b & 0xff).toString(16).padStart(2, '0').toUpperCase()).join(' ');
const short = (u) => String(u).slice(0, 8).toUpperCase();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const LS = { THEME: 'dualtron_theme', OPEN: 'dualtron_open', EKFV: 'dualtron_ekfv', PUBLOG: 'dualtron_publog', DEV: 'dualtron_device' };

let dev = null, server = null, chWrite = null, chNotify = null, busy = false;
let connected = false;
let pendingDeepAction = null;   // 'unlock' | 'lock' from a ?do= shortcut
let pollTimer = null;

// live device state, rebuilt from the reply frames (the command builders read the raw payloads from this)
const S = {
  // telemetry (0x00)
  battPct: null, speed: null, trip: null, odo: null, gear: null, current: null, voltage: null,
  power: null, rangeKm: null, fault: null,
  brakeOn: null, safeOn: null, hallErr: null, accErr: null, ctrlErr: null, motorErr: null,
  // system (0x01)
  capBits: null, poleCount: null, battVolt: null, wheelSize: null, maxGear: null, motorProtTemp: null,
  enableCCS: null, enablePAS: null,
  // user (0x02)
  topPct: null, zeroStart: null, isKm: null, torque: null, brakeLevel: null, softStart: null,
  abs: null, screenLight: null, autoOff: null, eco: null, acc: null, showVolt: null, dangerous: null,
  // controller page (0x05)
  controller: null, maxSpeed: null, displayVer: null, ctrlTemp: null, maxMotorTemp: null,
  maxCtrlTemp: null, timeOnce: null, avgSpeed: null, _ctPrev: null,
  // raw payloads kept for safe read-modify-write
  rawSystem: null, rawUser: null
};
function resetState() { for (const k of Object.keys(S)) S[k] = null; }

// --------------------------- log (eg-unlock redaction pipeline: scrub secrets + anonymize PII) ---------------------------
let logBuffer = [];   // { raw, cls }
let publicLog = true; // anonymize device name/id/MAC on display/copy/save (default on)
let diag = false;     // verbose diagnostics (default off)
function redact(text) {
  let s = String(text);
  if (dev && dev.id) s = s.split(dev.id).join('[redacted-id]');
  s = s.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[redacted-mac]');
  s = s.replace(/\b(secret|token|key|aes|pwd|password|pin|mac|serial|vin|uid|imei)\b(\s*[:=]\s*)("?)([^\s",]+)\3/gi,
    (m, k, sep) => k + sep + '[redacted]');
  s = s.replace(/\b[0-9A-Fa-f]{16,}\b/g, '[redacted-hex]');
  return s;
}
// Unconditional secret scrubber, runs at the source before the buffer (independent of the Public Log toggle).
function maskSecrets(text) {
  let s = String(text);
  s = s.replace(/eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, '[redacted-jwt]');
  s = s.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer ***');
  s = s.replace(/\b(access[_-]?token|refresh[_-]?token|token|jwt|password|passwd|pwd|secret|code|otp)\b(\s*[:=]\s*)("?)([^\s",}]+)\3/gi,
    (m, k, sep) => k + sep + '***');
  return s;
}
function anonymize(s) {
  if (!publicLog) return String(s).replace(/\x01/g, '');
  return redact(String(s).replace(/\x01[^\x01]*\x01/g, 'XX').replace(/\x01/g, ''));
}
function logLine(cls, text) {
  const safe = '[' + new Date().toTimeString().slice(0, 8) + '] ' + maskSecrets(text);
  logBuffer.push({ raw: safe, cls: cls });
  const el = $('log'); if (!el) return;
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = anonymize(safe) + '\n';
  el.appendChild(span); el.scrollTop = el.scrollHeight;
}
function renderLog() {
  const el = $('log'); if (!el) return;
  el.textContent = '';
  for (const e of logBuffer) { const span = document.createElement('span'); if (e.cls) span.className = e.cls; span.textContent = anonymize(e.raw) + '\n'; el.appendChild(span); }
  el.scrollTop = el.scrollHeight;
}
function logText() { return logBuffer.map(e => anonymize(e.raw)).join('\n'); }
const logTx = (b) => logLine('log-tx', '>>> ' + short(U.WRITE) + ' | ' + hex(b));
const logRx = (b) => logLine('log-rx', '<<< ' + short(U.NOTIFY) + ' | ' + hex(b));
const logSys = (t) => logLine('', '--- ' + t);
const logErr = (t) => logLine('log-err', '!!! ' + t);
const logDiag = (t) => { if (diag) logLine('', '... ' + t); };
// CRLF on Windows so the copied log pastes cleanly into Notepad (nv osNewline polish).
function osNewline() { return (navigator.platform || '').toLowerCase().indexOf('win') === 0 ? '\r\n' : '\n'; }
function saveLog() {
  try {
    const blob = new Blob([logText().split('\n').join(osNewline())], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'laufbursche42-dualtron-log.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    logSys('log saved');
  } catch (e) { logErr('save failed: ' + (e && e.message ? e.message : e)); }
}
function logDiagnosticHeader() {
  logLine('', '=== dualtron-unlock diagnostic ===');
  logLine('', 'build: ' + BUILD);
  logLine('', 'time: ' + new Date().toISOString());
  logLine('', 'userAgent: ' + (navigator.userAgent || '?'));
  logLine('', 'platform: ' + (navigator.platform || '?'));
  logLine('', 'webBluetooth: ' + (navigator.bluetooth ? 'yes' : 'no'));
  logLine('', 'protocol self-test: ' + (FRAME_OK ? 'OK' : 'FAILED'));
  logLine('', '================================');
}

// --------------------------- frame + obfuscation (PacketDataUtils.java:41-43, 1358-1368) ---------------------------
// 16-byte frame: [0]=0xAA | [1]=seed(0..9) | [2]=opcode | [3..13]=11 payload bytes, each (value+mask)&0xFF
//   | [14]=checksum=(sum of bytes[1..13])&0xFF | [15]=0xEE.
// mask = ((((seed+33)*73) ^ 169) & 249), carried in cleartext via the seed - reversible, not encryption.
function getMask(seed) { return ((((seed + 33) * 73) ^ 169) & 249) & 0xff; }
function buildFrame(op, values, seed) {
  if (seed == null) seed = Math.floor(Math.random() * 10);
  seed &= 0xff;
  const mask = getMask(seed);
  const vals = (values || []).slice(0, 11).map(v => v & 0xff);
  while (vals.length < 11) vals.push(0);
  const f = [0xaa, seed, op & 0xff];
  for (const v of vals) f.push((v + mask) & 0xff);
  let sum = 0; for (let i = 1; i <= 13; i++) sum += f[i] & 0xff;
  f.push(sum & 0xff);   // checksum
  f.push(0xee);         // footer
  return f;
}
// strict validator mirroring MyDeviceManager.java:313 + the checksum rule
function validFrame(f) {
  if (!f || f.length !== 16) return false;
  if (f[0] !== 0xaa || f[15] !== 0xee) return false;
  let sum = 0; for (let i = 1; i <= 13; i++) sum += f[i] & 0xff;
  return f[14] === (sum & 0xff);
}
// RX: strip the mask from the 11 payload bytes (PacketDataUtils.readData subtracts the mask)
function payloadOf(f) {
  const mask = getMask(f[1] & 0xff);
  const p = []; for (let i = 3; i <= 13; i++) p.push((f[i] - mask) & 0xff);
  return p;   // p[0..10]
}

// --------------------------- legal/region speed cap (system payload[0] bits 6-7) ---------------------------
// getSystemSpeedLimit (MyDeviceManager.java:228-240): 0=OFF, 0x80=20, 0xC0=22, else(0x40)=25 km/h.
const CAP_BITS = { off: 0x00, k25: 0x40, k22: 0xc0, k20: 0x80 };
function capLabel(bits) {
  if (bits == null) return null;
  const b = bits & 0xc0;
  if (b === 0x00) return t('capOff');
  if (b === 0x80) return '20 km/h';
  if (b === 0xc0) return '22 km/h';
  return '25 km/h';   // 0x40
}
const CONTROLLER_NAMES = ['RUISA_SQUARE', 'ZHAOYI_FOC', 'LINOU_SQUARE', 'HAIBO_FOC', 'HAIBO_FOC_2'];

// --------------------------- read requests + write builders ---------------------------
const REQ = { TELEMETRY: 0x00, SYSTEM: 0x01, USER: 0x02, DEV2: 0x05 };
// 0x81 system write mirrors the 0x01 read payload (device_system_write=129). We rebuild from the last raw
// system payload and change only the proven field, so other settings are preserved (read-modify-write).
function frameSystemWrite(mut) {
  if (!S.rawSystem) return null;
  const p = S.rawSystem.slice();
  mut(p);
  return buildFrame(0x81, p);
}
function frameSetCap(capBits) {
  return frameSystemWrite(p => { p[0] = (p[0] & 0x3f) | (capBits & 0xc0); });   // bits 6-7, keep poleCount
}
function frameSetMaxGear(gear) {
  return frameSystemWrite(p => { p[5] = (p[5] & ~0xe0 & 0xff) | ((gear << 5) & 0xe0); });   // bits 5-7
}
// CCS cruise byte4 bit6, PAS pedal-assist byte4 bit7 (setCmdSystemEnableCCS/PAS, PacketDataUtils.java:60-118)
function frameSetCCS(on) { return frameSystemWrite(p => { p[4] = on ? (p[4] | 0x40) : (p[4] & ~0x40 & 0xff); }); }
function frameSetPAS(on) { return frameSystemWrite(p => { p[4] = on ? (p[4] | 0x80) : (p[4] & ~0x80 & 0xff); }); }
// motor-protection temperature setpoint = system byte10 (setCmdSystemMotorProtect, PacketDataUtils.java:1433)
function frameSetMotorProt(temp) { return frameSystemWrite(p => { p[10] = temp & 0xff; }); }
// 0x82 user write (device_user_write=130, setCmdUserSet, PacketDataUtils.java:661-690): mirror the last read
// user payload, overwrite a selector byte[sel]=selVal and one data byte[idx]=val, re-add the mask + checksum.
function frameUserCmd(sel, selVal, idx, val) {
  if (!S.rawUser) return null;
  const p = S.rawUser.slice();
  p[sel] = selVal & 0xff;
  if (idx != null) p[idx] = val & 0xff;
  return buildFrame(0x82, p);
}
// top-speed percent: setCmdUserSetTopSpeed = setCmdUserSet(0,1,2,b) (PacketDataUtils.java:471)
function frameSetTopPct(pct) { return frameUserCmd(0, 1, 2, pct & 0xff); }

// --------------------------- RX parsers (de-masked payload offsets from MyDeviceManager.readData) ---------------------------
const OPCODE_LABEL = {
  0x00: 'telemetry', 0x01: 'system', 0x02: 'user', 0x03: 'light', 0x05: 'controller/max',
  0x07: 'temp/bms', 0x08: 'bms', 0x0a: 'user2', 0x0b: 'bms-warn', 0x0d: 'meter-name',
  0x81: 'system-wr echo', 0x82: 'user-wr echo', 0x83: 'light-wr echo'
};
function parseFrame(f) {
  const op = f[2];
  const p = payloadOf(f);
  if (op === 0x00) {                       // telemetry (MyDeviceManager.java:326-350)
    S.battPct = p[1] & 0x7f;               // :337 battery = iArr[1] & 127
    S.safeOn = ((p[1] >> 7) & 1) === 1;    // :331 safe mode active
    S.hallErr = ((p[0] >> 6) & 1) === 1;   // :328 hall sensor error
    S.brakeOn = ((p[0] >> 7) & 1) === 1;   // :329 brake lever pressed
    S.accErr = ((p[0] >> 5) & 1) === 1;    // :333 throttle error
    S.ctrlErr = ((p[0] >> 4) & 1) === 1;   // :334 controller error
    S.motorErr = ((p[0] >> 3) & 1) === 1;  // :335 motor error
    S.speed = p[6] & 0xff;
    S.trip = ((p[2] & 0xff) + (p[3] & 0x0f) * 256) / 10;
    S.gear = (p[3] >> 4) & 7;
    S.odo = ((p[3] >> 7) & 1) * 65536 + (p[4] & 0xff) * 256 + (p[5] & 0xff);
    S.current = p[8] & 0xff;
    S.voltage = p[9] & 0xff;               // :343 live pack voltage
    S.power = p[7] & 0xff;
    S.rangeKm = p[10] & 0xff;
    S.fault = p[0] & 0xff;                 // kept raw; the fault tile decodes the error bits above
  } else if (op === 0x01) {                // system / factory settings (MyDeviceManager.java:554-587)
    S.rawSystem = p.slice();
    S.poleCount = p[0] & 0x3f;             // :558 motor pole pairs
    S.capBits = p[0] & 0xc0;
    S.battVolt = p[1] & 0x7f;              // :560 nominal battery voltage (config)
    S.wheelSize = (((p[1] >> 7) & 1) * 256 + (p[2] & 0xff)) / 10;   // :578
    S.maxGear = (p[5] & 0xe0) >> 5;        // :577
    S.motorProtTemp = p[10] & 0xff;        // :571 motor-protect temperature setpoint
    S.enableCCS = ((p[4] >> 6) & 1) === 1; // :580 cruise control enabled
    S.enablePAS = ((p[4] >> 7) & 1) === 1; // :581 pedal/push assist enabled
  } else if (op === 0x02) {                // user settings (MyDeviceManager.java:352-422)
    S.rawUser = p.slice();
    S.topPct = p[2] & 0x7f;                // :356 speedLimited = iArr[2] & 127
    S.zeroStart = ((p[2] >> 7) & 1) === 1; // :357 zero-start / kick-to-start
    S.isKm = ((p[3] >> 3) & 1) !== 1;      // :360 unit km vs mile
    S.torque = p[3] & 7;                   // :363 torque strength
    S.brakeLevel = Math.min((p[3] & 0x70) >> 4, 5);   // :364-367 e-brake strength
    S.softStart = Math.min(p[4] & 7, 5);   // :371-374 soft-start level
    S.abs = (p[4] & 8) !== 0;              // :376 ABS
    S.screenLight = (p[4] & 0xe0) >> 5;    // :377 screen brightness level
    S.autoOff = p[5] & 31;                 // :380 auto power-off minutes
    S.eco = ((p[5] >> 5) & 1) === 1;       // :381 ECO
    S.acc = ((p[5] >> 6) & 1) === 1;       // :382 cruise (ACC)
    S.showVolt = ((p[5] >> 7) & 1) === 1;  // :384 show voltage on display
    S.dangerous = ((p[0] >> 6) & 1) === 1; // :388 hazard lights
  } else if (op === 0x05) {                // controller + max speed page (MyDeviceManager.java:483-540)
    const i29 = p[0] & 0xff;               // :484-490 controller temperature with glitch filter
    const prev = (S._ctPrev == null) ? i29 : S._ctPrev; S._ctPrev = i29;
    S.ctrlTemp = (Math.abs(prev - i29) < 30 && i29 < 200) ? i29 : 0;
    S.timeOnce = (p[2] & 0xff) * 256 + (p[1] & 0xff);   // :492 single-ride minutes
    S.maxSpeed = p[3] & 0xff;
    S.maxMotorTemp = p[6] & 0xff;          // :494
    S.maxCtrlTemp = p[7] & 0xff;           // :495
    const c = p[8] & 0xff; S.controller = CONTROLLER_NAMES[c] || ('0x' + c.toString(16));
    S.displayVer = p[9] & 0xff;            // :517 display version
    S.avgSpeed = (S.timeOnce > 0 && S.trip != null) ? ((S.trip * 60) / S.timeOnce) : null;   // :499
  }
}

// load-time self-test: the builder must match hand-computed vectors, every built frame must re-validate
const FRAME_OK = (function () {
  const eq = (a, b) => a.length === b.length && a.every((v, i) => (v & 0xff) === (b[i] & 0xff));
  // getMask: seed0=0xC0, seed1=0x19, seed2=0x50 (hand-derived).
  const s0 = getMask(0) === 0xc0, s1 = getMask(1) === 0x19, s2 = getMask(2) === 0x50;
  // v1: op 0x00, empty payload, seed 0 -> AA 00 00 then 11x C0, cksum (0+0+11*0xC0)&0xFF=0x40, EE
  const t1 = eq(buildFrame(0x00, [], 0),
    [0xaa, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x40, 0xee]);
  // v2: op 0x81, payload[0]=0x80 (20 km/h cap), seed 1, mask 0x19 -> byte3=0x99, byte4..13=0x19
  const t2 = eq(buildFrame(0x81, [0x80], 1),
    [0xaa, 0x01, 0x81, 0x99, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x15, 0xee]);
  // v3: op 0x82, payload[2]=0x3F (top-speed 63), seed 2, mask 0x50 -> byte5=0x8F, rest 0x50
  const t3 = eq(buildFrame(0x82, [0x00, 0x00, 0x3f], 2),
    [0xaa, 0x02, 0x82, 0x50, 0x50, 0x8f, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x33, 0xee]);
  return s0 && s1 && s2 && t1 && t2 && t3 &&
    validFrame(buildFrame(0x00, [], 0)) && validFrame(buildFrame(0x81, [0x80], 1));
})();

// =========================================================================================
//  END VERIFIED PROTOCOL CORE
// =========================================================================================

// --------------------------- tiles ---------------------------
const TILE_IDS = ['t-cap', 't-toppct', 't-speed', 't-batt', 't-volt', 't-livevolt', 't-gear', 't-maxgear',
  't-trip', 't-odo', 't-current', 't-power', 't-range', 't-wheel', 't-fault', 't-brake', 't-safe',
  't-controller', 't-maxspeed', 't-ctemp', 't-mmtemp', 't-mctemp', 't-ridetime', 't-avgspeed',
  't-poles', 't-dispver'];
function setTile(id, val) { const el = $(id); if (el) el.textContent = (val == null ? '-' : val); }
function resetTiles() { TILE_IDS.forEach(id => setTile(id, null)); }
// fault tile: decode the active error flags from the telemetry byte (MyDeviceManager.java:328-335)
function faultLabel() {
  if (S.fault == null) return null;
  const f = [];
  if (S.hallErr) f.push(t('errHall'));
  if (S.accErr) f.push(t('errAcc'));
  if (S.ctrlErr) f.push(t('errCtrl'));
  if (S.motorErr) f.push(t('errMotor'));
  return f.length ? f.join(', ') : t('valNone');
}
function refreshTiles() {
  setTile('t-cap', capLabel(S.capBits));
  setTile('t-toppct', S.topPct == null ? null : S.topPct + ' %');
  setTile('t-speed', S.speed == null ? null : S.speed + ' km/h');
  setTile('t-batt', S.battPct == null ? null : S.battPct + ' %');
  setTile('t-volt', S.battVolt == null ? null : S.battVolt + ' V');
  setTile('t-livevolt', S.voltage == null ? null : S.voltage + ' V');
  setTile('t-gear', S.gear == null ? null : String(S.gear));
  setTile('t-maxgear', S.maxGear == null ? null : String(S.maxGear));
  setTile('t-trip', S.trip == null ? null : S.trip.toFixed(1) + ' km');
  setTile('t-odo', S.odo == null ? null : S.odo + ' km');
  setTile('t-current', S.current == null ? null : String(S.current));
  setTile('t-power', S.power == null ? null : String(S.power));
  setTile('t-range', S.rangeKm == null ? null : S.rangeKm + ' km');
  setTile('t-wheel', S.wheelSize == null ? null : S.wheelSize.toFixed(1) + '"');
  setTile('t-fault', faultLabel());
  setTile('t-brake', S.brakeOn == null ? null : (S.brakeOn ? t('valYes') : t('valNo')));
  setTile('t-safe', S.safeOn == null ? null : (S.safeOn ? t('valOn') : t('valOff')));
  setTile('t-controller', S.controller == null ? null : String(S.controller));
  setTile('t-maxspeed', S.maxSpeed == null ? null : S.maxSpeed + ' km/h');
  setTile('t-ctemp', S.ctrlTemp == null ? null : S.ctrlTemp + ' °C');
  setTile('t-mmtemp', S.maxMotorTemp == null ? null : S.maxMotorTemp + ' °C');
  setTile('t-mctemp', S.maxCtrlTemp == null ? null : S.maxCtrlTemp + ' °C');
  setTile('t-ridetime', S.timeOnce == null ? null : S.timeOnce + ' min');
  setTile('t-avgspeed', S.avgSpeed == null ? null : S.avgSpeed.toFixed(1) + ' km/h');
  setTile('t-poles', S.poleCount == null ? null : String(S.poleCount));
  setTile('t-dispver', S.displayVer == null ? null : String(S.displayVer));
}

// last frame bytes kept per opcode (updated on RX; no UI consumer in the canonical shell)
const seenFrames = {};   // opcode -> last frame bytes

// --------------------------- i18n ---------------------------
let lang = 'de';
function table() { return (window.I18N && window.I18N[lang]) || {}; }
function t(key) { const v = table()[key]; return (typeof v === 'string') ? v : ''; }
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(n => { const v = t(n.getAttribute('data-t')); if (/[<&]/.test(v)) n.innerHTML = v; else n.textContent = v; }); // scan-ok: curated i18n values with markup (banner/disclaimer links); own table, not user input
  document.querySelectorAll('[data-t-ph]').forEach(n => { const v = t(n.getAttribute('data-t-ph')); if (v) n.setAttribute('placeholder', v); });
  ['GUIDE', 'README', 'LICENSE', 'PRIVACY', 'TRADEMARKS', 'DISCLAIMER'].forEach(name => { const el = $('link-' + name.toLowerCase()); if (el) el.href = docFile(name); });
  { const el = $('langs'); if (el) el.setAttribute('aria-label', t('langGroup')); }
  { const el = $('build-ver'); if (el) el.textContent = t('buildLabel') + ' ' + BUILD; }
  document.querySelectorAll('#langs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  syncSettings(); refreshTiles(); updateSpeedUI(); updateShortcuts();
  { const el = $('status'); setStatus(el ? el.dataset.state : 'disconnected'); }
  { const dark = document.documentElement.getAttribute('data-theme') !== 'light'; const el = $('btn-theme'); if (el) { el.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); el.title = el.getAttribute('aria-label'); } }
}
function initLangSwitch() { document.querySelectorAll('#langs button').forEach(b => b.addEventListener('click', () => { lang = b.dataset.lang; applyLang(); })); }

// --------------------------- theme ---------------------------
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const b = $('btn-theme');
  if (b) { b.textContent = dark ? '\u2600' : '\u263E'; b.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); b.title = b.getAttribute('aria-label'); }
  try { localStorage.setItem(LS.THEME, dark ? 'dark' : 'light'); } catch (e) {}
}
function initTheme() {
  let saved = null; try { saved = localStorage.getItem(LS.THEME); } catch (e) {}
  applyTheme(saved !== 'light');
  const b = $('btn-theme'); if (b) b.addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light'));
}

// --------------------------- status ---------------------------
function statusLabel(s) {
  const map = { disconnected: 'stDisconnected', connecting: 'stConnecting', linking: 'stLinking', connected: 'stConnected', 'no-service': 'stNoService' };
  return t(map[s] || 'stDisconnected') || s;
}
function setStatus(s) {
  const el = $('status'); if (el) { el.dataset.state = s; el.textContent = statusLabel(s); }
  const cb = $('btn-conn');
  if (cb) { const on = (s === 'connecting' || s === 'linking' || s === 'connected'); cb.textContent = on ? t('btnDisconnect') : t('btnConnect'); cb.dataset.act = on ? 'disconnect' : 'connect'; }
}
function setControlsEnabled(on) {
  // cards hidden until connected (header/intro/connect/shortcut/log stay visible)
  ['live-card', 'batt-card', 'more-card', 'raw-card'].forEach(id => { const el = $(id); if (el) el.hidden = !on; });
  document.querySelectorAll('[data-conn]').forEach(e => { e.disabled = !on; });
}

// --------------------------- connect (acceptAll + GATT service is the real gate; 4x retry) ---------------------------
async function connect() {
  if (!navigator.bluetooth) { logErr(t('errNoWebBt')); return; }
  try {
    setStatus('connecting');
    const showAll = ($('showall') || {}).checked;
    const opts = showAll
      ? { acceptAllDevices: true, optionalServices: CANDIDATE_SERVICES }
      : { filters: [{ services: [U.SERVICE] }], optionalServices: CANDIDATE_SERVICES };
    dev = await navigator.bluetooth.requestDevice(opts);
    dev.addEventListener('gattserverdisconnected', onDisconnected);
    try { localStorage.setItem(LS.DEV, dev.id); } catch (e) {}
    logSys('device: \x01' + (dev.name || '(no name)') + '\x01');
    setStatus('linking');
    await connectGatt();
    setStatus('connected'); connected = true;
    setControlsEnabled(true);
    { const el = $('devinfo'); if (el) el.textContent = t('devPrefix') + ' \x01' + (dev.name || 'DUALTRON') + '\x01'; }
    logSys('connected, subscribed to ' + short(U.NOTIFY));
    startPolling();
    await maybeRunDeepAction();
  } catch (e) {
    logErr('connect failed: ' + (e && e.message ? e.message : e));
    connected = false; setStatus('disconnected'); setControlsEnabled(false);
  }
}
// tolerate the Android discovery race (nv 4x retry): service can be briefly absent right after link.
async function connectGatt() {
  let lastErr = null;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      server = await dev.gatt.connect();
      const svc = await resolveService(server);
      if (!svc) { setStatus('no-service'); throw new Error('DUALTRON service ' + short(U.SERVICE) + ' not found'); }
      chWrite = await svc.getCharacteristic(U.WRITE);
      chNotify = await svc.getCharacteristic(U.NOTIFY);
      await chNotify.startNotifications();
      chNotify.addEventListener('characteristicvaluechanged', onCharValue);
      return;
    } catch (e) {
      lastErr = e; logDiag('connect attempt ' + attempt + ' failed: ' + (e && e.message ? e.message : e));
      try { if (dev.gatt.connected) dev.gatt.disconnect(); } catch (_) {}
      await sleep(400);
    }
  }
  throw lastErr || new Error('gatt connect failed');
}
async function resolveService(srv) {
  for (const uuid of CANDIDATE_SERVICES) { try { return await srv.getPrimaryService(uuid); } catch (_) {} }
  return null;
}
function onDisconnected() {
  connected = false; chWrite = null; chNotify = null; stopPolling();
  setStatus('disconnected'); setControlsEnabled(false);
  resetState(); resetTiles(); clearAcks(); for (const k of Object.keys(seenFrames)) delete seenFrames[k];
  updateSpeedUI();
  const el = $('devinfo'); if (el) el.textContent = '';
  logSys('disconnected');
}
function disconnect() { if (dev && dev.gatt.connected) dev.gatt.disconnect(); }

// poll the device: it answers read requests, so ask for telemetry + the settings pages (no auto-stream proven)
function startPolling() {
  const askAll = () => { for (const op of [REQ.TELEMETRY, REQ.SYSTEM, REQ.USER, REQ.DEV2]) transmit(buildFrame(op, []), 'read 0x' + op.toString(16), null, true); };
  askAll();
  stopPolling();
  pollTimer = setInterval(() => { if (connected && chWrite) transmit(buildFrame(REQ.TELEMETRY, []), 'poll telemetry', null, true); }, 1500);
}
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

// --------------------------- notify + ACK ---------------------------
let rxBuf = [];
function onCharValue(ev) {
  const b = Array.from(new Uint8Array(ev.target.value.buffer));
  logRx(b);
  for (const x of b) rxBuf.push(x);
  // frames are a fixed 16 bytes; reassemble by the 0xAA header + 0xEE footer
  while (rxBuf.length >= 16) {
    if (rxBuf[0] !== 0xaa) { rxBuf.shift(); continue; }
    const frame = rxBuf.slice(0, 16);
    if (frame[15] !== 0xee) { rxBuf.shift(); continue; }
    rxBuf = rxBuf.slice(16);
    if (!validFrame(frame)) { logDiag('bad checksum, dropped: ' + hex(frame)); continue; }
    handleFrame(frame);
  }
}
function handleFrame(frame) {
  const op = frame[2];
  parseFrame(frame);
  seenFrames[op] = frame;
  resolveAck('op:' + op);
  refreshTiles(); updateSpeedUI(); syncSettings();
}
const pendingAcks = new Map();
const ACK_TIMEOUT_MS = 3000;
function armAck(key, label) {
  clearAckTimer(key);
  const timer = setTimeout(() => { pendingAcks.delete(key); logSys(label + ': ' + t('ackNone')); }, ACK_TIMEOUT_MS);
  pendingAcks.set(key, { timer, label });
}
function resolveAck(key) { const a = pendingAcks.get(key); if (a) { clearTimeout(a.timer); pendingAcks.delete(key); logSys(a.label + ': ' + t('ackOk')); } }
function clearAckTimer(key) { const a = pendingAcks.get(key); if (a) { clearTimeout(a.timer); pendingAcks.delete(key); } }
function clearAcks() { for (const a of pendingAcks.values()) clearTimeout(a.timer); pendingAcks.clear(); }

// --------------------------- transmit (single funnel: log TX, arm ack, write) ---------------------------
async function writeFrame(bytes) {
  const arr = Uint8Array.from(bytes);
  // Dualtron writes WITH response (BlueService.wirteData); fall back if the stack reports otherwise.
  if (chWrite.properties.write) return chWrite.writeValueWithResponse(arr);
  if (chWrite.properties.writeWithoutResponse) return chWrite.writeValueWithoutResponse(arr);
  return chWrite.writeValue(arr);
}
async function transmit(bytes, label, ackKey, quiet) {
  if (!connected || !chWrite) { if (!quiet) logErr(t('errNotConnected')); return; }
  if (!quiet) logTx(bytes); else logDiag('>>> ' + hex(bytes));
  if (ackKey) armAck(ackKey, label);
  try { await writeFrame(bytes); if (!quiet) logSys(label + ': ' + t('txSent')); }
  catch (e) { clearAckTimer(ackKey); if (!quiet) logErr(label + ' ' + t('txFailed') + ': ' + (e && e.message ? e.message : e)); }
}
// serialize writes on the characteristic (eg guard mutex; vr/ap/vmax omit it)
async function guard(fn) { if (busy) return; busy = true; try { await fn(); } catch (e) { logErr(e && e.message ? e.message : String(e)); } finally { busy = false; } }

// --------------------------- commands ---------------------------
// All writes are read-modify-write: need the matching settings read first, then re-request it to confirm.
async function setCap(capBits, label) {
  if (!S.rawSystem) { logErr(t('errNoSystem')); return; }
  const f = frameSetCap(capBits); if (!f) return;
  await transmit(f, label, 'op:1');
  await transmit(buildFrame(REQ.SYSTEM, []), 'read system', null, true);
}
async function setMaxGear(gear) {
  if (!S.rawSystem) { logErr(t('errNoSystem')); return; }
  const f = frameSetMaxGear(gear); if (!f) return;
  await transmit(f, t('setMaxGear') + ' ' + gear, 'op:1');
  await transmit(buildFrame(REQ.SYSTEM, []), 'read system', null, true);
}
async function setTopPct(pct) {
  if (!S.rawUser) { logErr(t('errNoUser')); return; }
  const f = frameSetTopPct(pct); if (!f) return;
  await transmit(f, t('topLabel') + ' ' + pct + ' %', 'op:2');
  await transmit(buildFrame(REQ.USER, []), 'read user', null, true);
}
// generic settings senders: send one proven write frame on its opcode, then re-read that page to confirm.
async function sendUser(frame, label) {
  if (!S.rawUser) { logErr(t('errNoUser')); return; }
  if (!frame) return;
  await transmit(frame, label, 'op:2');
  await transmit(buildFrame(REQ.USER, []), 'read user', null, true);
}
async function sendSystem(frame, label) {
  if (!S.rawSystem) { logErr(t('errNoSystem')); return; }
  if (!frame) return;
  await transmit(frame, label, 'op:1');
  await transmit(buildFrame(REQ.SYSTEM, []), 'read system', null, true);
}
// proven writes (PacketDataUtils.java). bool selectors mirror setCmdUserSet(sel,selVal,idx,val).
const USER_SETTINGS = [
  { btn: 'btn-startmode', in: 'startmode-in', kind: 'bool', warn: 'warnStartMode', label: 'set_startmode', frame: on => frameUserCmd(0, 2, 2, on ? 128 : 0) },      // :467
  { btn: 'btn-unit', in: 'unit-in', kind: 'unit', warn: 'warnUnit', label: 'set_unit', frame: km => frameUserCmd(0, 8, 3, km ? 0 : 8) },                             // :459
  { btn: 'btn-torque', in: 'torque-in', kind: 'int', min: 0, max: 7, warn: 'warnTorque', err: 'errTorqueRange', label: 'set_torque', frame: v => frameUserCmd(0, 4, 3, v) },        // :463
  { btn: 'btn-brake', in: 'brake-in', kind: 'int', min: 0, max: 5, warn: 'warnBrake', err: 'errBrakeRange', label: 'set_brake', frame: v => frameUserCmd(0, 16, 3, v) },            // :451
  { btn: 'btn-softstart', in: 'softstart-in', kind: 'int', min: 0, max: 5, warn: 'warnSoftStart', err: 'errSoftRange', label: 'set_softstart', frame: v => frameUserCmd(0, 64, 4, v) }, // :447
  { btn: 'btn-screen', in: 'screen-in', kind: 'int', min: 0, max: 7, warn: 'warnScreen', err: 'errScreenRange', label: 'set_screenlight', frame: v => frameUserCmd(1, 1, 4, (v << 5) & 0xff) }, // :547
  { btn: 'btn-autooff', in: 'autooff-in', kind: 'int', min: 0, max: 31, warn: 'warnAutoOff', err: 'errAutoOffRange', label: 'set_autooff', frame: v => frameUserCmd(1, 2, 5, v) },  // :543
  { btn: 'btn-abs', in: 'abs-in', kind: 'bool', warn: 'warnAbs', label: 'set_abs', frame: on => frameUserCmd(0, 128, 4, on ? 8 : 0) },                               // :443
  { btn: 'btn-eco', in: 'eco-in', kind: 'bool', warn: 'warnEco', label: 'set_eco', frame: on => frameUserCmd(1, 4, 5, on ? 32 : 0) },                               // :539
  { btn: 'btn-acc', in: 'acc-in', kind: 'bool', warn: 'warnAcc', label: 'set_acc', frame: on => frameUserCmd(1, 8, 5, on ? 64 : 0) },                               // :527
  { btn: 'btn-showvolt', in: 'showvolt-in', kind: 'bool', warn: 'warnShowVolt', label: 'set_showvolt', frame: on => frameUserCmd(1, 16, 5, on ? 128 : 0) },         // :491
  { btn: 'btn-dangerous', in: 'dangerous-in', kind: 'bool', warn: 'warnDangerous', label: 'set_dangerous', frame: on => frameUserCmd(1, 128, 7, on ? 64 : 0) }      // :487
];
const SYSTEM_SETTINGS = [
  { btn: 'btn-ccs', in: 'ccs-in', kind: 'bool', warn: 'warnCcs', label: 'set_ccs', frame: on => frameSetCCS(on) },                                                  // :60
  { btn: 'btn-pas', in: 'pas-in', kind: 'bool', warn: 'warnPas', label: 'set_pas', frame: on => frameSetPAS(on) },                                                  // :90
  { btn: 'btn-motorprot', in: 'motorprot-in', kind: 'int', min: 0, max: 255, warn: 'warnMotorProt', err: 'errMotorProtRange', label: 'set_motorprot', frame: v => frameSetMotorProt(v) } // :1433
];
function wireSetting(s, sender) {
  const b = $(s.btn); if (!b) return;
  b.addEventListener('click', () => guard(async () => {
    let val;
    if (s.kind === 'bool') val = (($(s.in) || {}).value === 'on');
    else if (s.kind === 'unit') val = (($(s.in) || {}).value !== 'mi');
    else { const v = parseInt(($(s.in) || {}).value, 10); if (!(v >= s.min && v <= s.max)) { logErr(t(s.err)); return; } val = v; }
    const f = s.frame(val); if (!f) { logErr(t(sender === sendUser ? 'errNoUser' : 'errNoSystem')); return; }
    if (!await confirmRisky(t(s.warn))) return;
    await sender(f, t(s.label));
  }));
}

// --------------------------- speed card (region/legal cap + top-speed percent) ---------------------------
function updateSpeedUI() {
  const info = $('speed-current');
  if (info) info.textContent = (S.capBits == null) ? t('speedCurUnknown') : (t('speedCurPrefix') + ' ' + capLabel(S.capBits));
  const b = $('btn-toggle'); if (!b) return;
  // unknown or already capped -> offer unlock (set OFF); if OFF -> offer lock to the eKFV field
  const locked = (S.capBits == null) ? false : ((S.capBits & 0xc0) !== 0x00);
  b.dataset.mode = locked ? 'unlock' : 'lock';
  b.textContent = locked ? t('btnUnlock') : t('btnLock');
}

// --------------------------- settings (static rows; value mirrored from the device report) ---------------------------
// Only proven register writes get a named row: max gear (0x81 byte5). The input shows the current value
// once the scooter has reported it; the write is read-modify-write and re-reads to confirm.
function syncInt(id, v) { const el = $(id); if (el && document.activeElement !== el && v != null) el.value = String(v); }
function syncBool(id, v) { const el = $(id); if (el && document.activeElement !== el && v != null) el.value = v ? 'on' : 'off'; }
function syncUnit(id, v) { const el = $(id); if (el && document.activeElement !== el && v != null) el.value = v ? 'km' : 'mi'; }
function syncSettings() {
  syncInt('maxgear-in', S.maxGear);
  syncBool('startmode-in', S.zeroStart);
  syncUnit('unit-in', S.isKm);
  syncInt('torque-in', S.torque);
  syncInt('brake-in', S.brakeLevel);
  syncInt('softstart-in', S.softStart);
  syncInt('screen-in', S.screenLight);
  syncInt('autooff-in', S.autoOff);
  syncBool('abs-in', S.abs);
  syncBool('eco-in', S.eco);
  syncBool('acc-in', S.acc);
  syncBool('showvolt-in', S.showVolt);
  syncBool('dangerous-in', S.dangerous);
  syncBool('ccs-in', S.enableCCS);
  syncBool('pas-in', S.enablePAS);
  syncInt('motorprot-in', S.motorProtTemp);
}

// --------------------------- engine level (opcode read + raw verbatim + free builder) ---------------------------
async function cmdRegRead() {
  const op = parseInt(($('reg-op') || {}).value, 16);
  if (isNaN(op)) { logErr(t('errBadOp')); return; }
  await transmit(buildFrame(op & 0xff, []), t('regReadLabel') + ' 0x' + (op & 0xff).toString(16));
}
function hexToBytes(s) {
  const clean = String(s).replace(/[^0-9a-fA-F]/g, '');   // strip spaces/punctuation
  const out = []; for (let i = 0; i + 2 <= clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));   // pairs; drop a dangling nibble
  return out;
}
async function cmdRaw() {
  const bytes = hexToBytes(($('raw-in') || {}).value || '');
  if (!bytes.length) { logErr(t('errNoBytes')); return; }
  await transmit(bytes, t('rawLabel'));   // sent verbatim, no header/checksum added
}
async function cmdFree() {
  const op = parseInt(($('free-op') || {}).value, 16);
  if (isNaN(op)) { logErr(t('errBadOp')); return; }
  const payload = hexToBytes(($('free-payload') || {}).value || '');
  await transmit(buildFrame(op, payload), t('freeLabel') + ' 0x' + (op & 0xff).toString(16));   // proper 0xAA frame + mask + checksum
}

// --------------------------- shortcut deep-link (?do=unlock|lock) ---------------------------
function parseDeepLink() {
  const q = new URLSearchParams(location.search); let a = q.get('do');
  if (!a && location.hash) { const m = location.hash.match(/do=([a-z]+)/i); if (m) a = m[1]; }
  if (!a) return;
  a = a.toLowerCase();
  if (a === 'unlock' || a === 'fast') pendingDeepAction = 'unlock';
  else if (a === 'lock' || a === 'slow') pendingDeepAction = 'lock';
}
async function maybeRunDeepAction() {
  if (!pendingDeepAction) return;
  const act = pendingDeepAction; pendingDeepAction = null;
  // the write needs the system read first; the poll fires it on connect, give it a beat
  if (!S.rawSystem) await sleep(1200);
  if (act === 'unlock') { await guard(() => setCap(CAP_BITS.off, t('btnUnlock'))); }
  else { await guard(() => setCap(CAP_BITS.k20, t('btnLock'))); }
}
async function tryAutoReconnect() {
  if (!pendingDeepAction || !navigator.bluetooth || !navigator.bluetooth.getDevices) return;
  try {
    const list = await navigator.bluetooth.getDevices(); let saved = null; try { saved = localStorage.getItem(LS.DEV); } catch (e) {}
    const d = list.find(x => x.id === saved) || list[0]; if (!d) return;
    dev = d; dev.addEventListener('gattserverdisconnected', onDisconnected);
    setStatus('linking'); await connectGatt(); setStatus('connected'); connected = true; setControlsEnabled(true);
    logSys('auto-reconnect (shortcut)'); startPolling(); await maybeRunDeepAction();
  } catch (e) { logDiag('auto-reconnect skipped: ' + (e && e.message ? e.message : e)); }
}
function updateShortcuts() {
  const base = location.origin + location.pathname;
  const set = (id, action) => { const el = $(id); if (el) el.textContent = 'bluefy://open?url=' + encodeURIComponent(base + '?do=' + action); };
  set('sc-unlock', 'unlock'); set('sc-lock', 'lock');
}

// --------------------------- confirm dialog (themed; window.confirm fallback) ---------------------------
function confirmRisky(msg) {
  return new Promise(resolve => {
    const dlg = $('confirm'); const body = $('confirm-body');
    if (!dlg || !dlg.showModal) { resolve(window.confirm(msg)); return; }
    if (body) body.textContent = msg;
    const ok = $('confirm-ok'), cancel = $('confirm-x'), no = $('confirm-no');
    const done = (v) => { dlg.close(); ok.removeEventListener('click', onOk); if (no) no.removeEventListener('click', onNo); if (cancel) cancel.removeEventListener('click', onNo); resolve(v); };
    const onOk = () => done(true), onNo = () => done(false);
    ok.addEventListener('click', onOk); if (no) no.addEventListener('click', onNo); if (cancel) cancel.addEventListener('click', onNo);
    dlg.showModal();
  });
}

// --------------------------- doc viewer (markdown of our own docs) ---------------------------
const DOC_TITLES = { 'GUIDE.de.md': 'footGuide', 'GUIDE.en.md': 'footGuide', 'README.md': 'footReadme', 'LICENSE.de.md': 'footLicense', 'LICENSE.md': 'footLicense', 'PRIVACY.de.md': 'footPrivacy', 'PRIVACY.md': 'footPrivacy', 'TRADEMARKS.de.md': 'footTrademarks', 'TRADEMARKS.md': 'footTrademarks', 'DISCLAIMER.de.md': 'footDisclaimer', 'DISCLAIMER.md': 'footDisclaimer' };
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const slug = s => s.toLowerCase().trim().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-');
function docFile(name) { if (name === 'README') return 'README.md'; if (name === 'GUIDE') return 'GUIDE.' + lang + '.md'; return name + (lang === 'de' ? '.de.md' : '.md'); }
const esc = escHtml;
// inlineMd receives ALREADY-escaped text (mdToHtml escapes first); DOC_TITLES hrefs stay in-modal.
function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (m, text, href) {
      if (DOC_TITLES[href]) return '<a href="' + href + '" data-docfile="' + href + '">' + text + '</a>';
      return '<a href="' + href + '" target="_blank" rel="noopener">' + text + '</a>';
    });
}
function mdToHtml(md) {
  var codeBlocks = [];
  // 1) pull fenced code blocks out first so their content is never treated as markdown
  md = String(md).replace(/```[^\n]*\n?([\s\S]*?)```/g, function (m, code) {
    var i = codeBlocks.length;
    codeBlocks.push('<pre><code>' + esc(code.replace(/\n$/, '')) + '</code></pre>');
    return '\x00CB' + i + '\x00';
  });
  var lines = md.split(/\r?\n/);
  var out = [], para = [], list = null;
  function flushPara() { if (para.length) { out.push('<p>' + inlineMd(esc(para.join(' '))) + '</p>'); para = []; } }
  function flushList() { if (list) { out.push('<' + list.type + '>' + list.items.join('') + '</' + list.type + '>'); list = null; } }
  function isTableSep(s) { var tt = s.replace(/\s/g, ''); return /^\|?:?-+:?(\|:?-+:?)+\|?$/.test(tt); }
  function splitRow(s) { return s.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(function (c) { return c.trim(); }); }
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    var cb = ln.match(/^\x00CB(\d+)\x00$/);
    if (cb) { flushPara(); flushList(); out.push(codeBlocks[Number(cb[1])]); continue; }
    if (/^\s*$/.test(ln)) { flushPara(); flushList(); continue; }
    var h = ln.match(/^(#{1,6})\s+(.*)$/);
    if (h) { flushPara(); flushList(); var lvl = Math.min(h[1].length, 4); out.push('<h' + lvl + '>' + inlineMd(esc(h[2])) + '</h' + lvl + '>'); continue; }
    if (/^---+$/.test(ln.trim())) { flushPara(); flushList(); out.push('<hr>'); continue; }
    if (ln.indexOf('|') >= 0 && i + 1 < lines.length && isTableSep(lines[i + 1])) {   // GFM table: header, |---| sep, rows
      flushPara(); flushList();
      var head = splitRow(ln); i++;   // consume the separator row
      var body = '';
      while (i + 1 < lines.length && lines[i + 1].indexOf('|') >= 0 && lines[i + 1].trim() !== '') {
        body += '<tr>' + splitRow(lines[++i]).map(function (c) { return '<td>' + inlineMd(esc(c)) + '</td>'; }).join('') + '</tr>';
      }
      out.push('<table><thead><tr>' + head.map(function (c) { return '<th>' + inlineMd(esc(c)) + '</th>'; }).join('') + '</tr></thead><tbody>' + body + '</tbody></table>');
      continue;
    }
    if (/^\s*>/.test(ln)) {                             // merge consecutive > lines into ONE callout
      flushPara(); flushList();
      var q = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) { q.push(lines[i].replace(/^\s*>\s?/, '')); i++; }
      i--;                                              // step back; the for-loop re-increments
      while (q.length && /^\s*$/.test(q[0])) q.shift();
      while (q.length && /^\s*$/.test(q[q.length - 1])) q.pop();
      if (q.length) out.push('<blockquote>' + mdToHtml(q.join('\n')) + '</blockquote>');  // inner rendered as markdown
      continue;
    }
    var ul = ln.match(/^\s*[-*]\s+(.*)$/);
    var ol = ln.match(/^\s*\d+\.\s+(.*)$/);
    if (ul || ol) {
      flushPara();
      var type = ul ? 'ul' : 'ol';
      if (!list || list.type !== type) { flushList(); list = { type: type, items: [] }; }
      list.items.push('<li>' + inlineMd(esc((ul ? ul[1] : ol[1]))) + '</li>');
      continue;
    }
    para.push(ln.trim());
  }
  flushPara(); flushList();
  return out.join('\n');
}
const docCache = {};
async function openDocFile(file) {
  const dlg = $('doc'); const titleEl = $('doc-title'); const bodyEl = $('doc-body');
  titleEl.textContent = t(DOC_TITLES[file] || 'footReadme');
  if (lang === 'de' && /\.md$/.test(file) && !/\.de\.md$/.test(file) && file !== 'README.md') titleEl.textContent += ' (englisch)';
  try { if (!docCache[file]) { const r = await fetch(file); docCache[file] = await r.text(); } bodyEl.innerHTML = mdToHtml(docCache[file]); } // scan-ok: own in-repo markdown rendered via mdToHtml; not user input
  catch (e) { bodyEl.textContent = 'Could not load ' + file; }
  if (dlg.showModal) dlg.showModal();
}
function wireDocViewer() {
  // delegated: footer doc links, the intro guide link (injected by i18n at runtime), in-doc links, disclaimer
  document.addEventListener('click', e => {
    const d = e.target.closest('a[data-doc]'); if (d) { e.preventDefault(); openDocFile(docFile(d.getAttribute('data-doc'))); return; }
    const df = e.target.closest('a[data-docfile]'); if (df) { e.preventDefault(); openDocFile(df.getAttribute('data-docfile')); return; }
    const disc = e.target.closest('[data-open-disclaimer]'); if (disc) { e.preventDefault(); openDocFile(docFile('DISCLAIMER')); return; }
  });
  ['doc-x', 'doc-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', () => $('doc').close()); });
}

// --------------------------- help modal ---------------------------
const HELP = ['live', 'speed', 'more', 'raw', 'publiclog', 'diaglog'];
function openHelp(key) { openHelpText(t('help_' + key + '_t'), t('help_' + key + '_b')); }
function openHelpText(title, body) {
  const dlg = $('help'); $('help-title').textContent = title || ''; const b = $('help-body'); if (/[<&]/.test(body || '')) b.innerHTML = body; else b.textContent = body || ''; // scan-ok: curated i18n help text; own table, not user input
  if (dlg.showModal) dlg.showModal();
}
function closeHelp() { const d = $('help'); if (d) d.close(); }

// --------------------------- init ---------------------------
window.addEventListener('DOMContentLoaded', () => {
  initLangSwitch(); initTheme(); wireDocViewer();
  applyLang(); setStatus('disconnected'); resetTiles();
  logDiagnosticHeader();
  if (!FRAME_OK) logErr('protocol self-test FAILED - builders do not match known vectors; do not trust writes');

  $('btn-conn').addEventListener('click', () => { if ($('btn-conn').dataset.act === 'disconnect') disconnect(); else guard(connect); });

  // region/legal cap: Unlock sets OFF, Lock sets the eKFV-style 20 km/h cap
  $('btn-toggle').addEventListener('click', () => guard(async () => {
    const unlock = ($('btn-toggle').dataset.mode === 'unlock');
    if (!await confirmRisky(t(unlock ? 'warnUnlock' : 'warnLock'))) return;
    await setCap(unlock ? CAP_BITS.off : CAP_BITS.k20, unlock ? t('btnUnlock') : t('btnLock'));
  }));
  // explicit cap selector
  { const b = $('btn-setcap'); if (b) b.addEventListener('click', () => guard(async () => {
      const key = ($('cap-in') || {}).value || 'off';
      if (!await confirmRisky(t('warnCap'))) return;
      await setCap(CAP_BITS[key] != null ? CAP_BITS[key] : 0, t('capLabelSet'));
  })); }
  // top-speed percent
  { const b = $('btn-toppct'); if (b) b.addEventListener('click', () => guard(async () => {
      const v = parseInt(($('toppct-in') || {}).value, 10);
      if (!(v >= 0 && v <= 100)) { logErr(t('errPctRange')); return; }
      if (!await confirmRisky(t('warnTopPct'))) return;
      await setTopPct(Math.min(v, 100));
  })); }

  // max gear (proven system write 0x81 byte5)
  { const b = $('btn-maxgear'); if (b) b.addEventListener('click', () => guard(async () => {
      const v = parseInt(($('maxgear-in') || {}).value, 10);
      if (!(v >= 1 && v <= 5)) { logErr(t('errGearRange')); return; }
      if (!await confirmRisky(t('warnMaxGear'))) return;
      await setMaxGear(v);
  })); }

  // all other proven ride/user settings + system settings (declarative wiring)
  USER_SETTINGS.forEach(s => wireSetting(s, sendUser));
  SYSTEM_SETTINGS.forEach(s => wireSetting(s, sendSystem));

  // engine level: read an opcode, send a raw frame, build a frame
  { const b = $('btn-reg-read'); if (b) b.addEventListener('click', () => guard(cmdRegRead)); }
  { const b = $('btn-raw'); if (b) b.addEventListener('click', () => guard(cmdRaw)); }
  { const b = $('btn-free'); if (b) b.addEventListener('click', () => guard(cmdFree)); }

  document.querySelectorAll('.help-btn[data-help]').forEach(btn => btn.addEventListener('click', () => openHelp(btn.getAttribute('data-help'))));
  ['help-x', 'help-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', closeHelp); });

  { const cb = $('public-log'); if (cb) { let saved = null; try { saved = localStorage.getItem(LS.PUBLOG); } catch (e) {} publicLog = saved !== '0'; cb.checked = publicLog; cb.addEventListener('change', () => { publicLog = cb.checked; try { localStorage.setItem(LS.PUBLOG, cb.checked ? '1' : '0'); } catch (e) {} logSys('public-log: ' + (cb.checked ? 'on (anonymizing device name/id)' : 'off')); renderLog(); }); } }
  { const cb = $('showall'); if (cb) cb.addEventListener('change', () => { logSys('show-all-frames: ' + (cb.checked ? 'on' : 'off')); renderLog(); }); }
  { const cb = $('diag-log'); if (cb) { cb.addEventListener('change', () => { diag = cb.checked; logSys(diag ? 'diagnostic log on' : 'diagnostic log off'); }); } }
  { const b = $('btn-clear-log'); if (b) b.addEventListener('click', () => { logBuffer = []; $('log').textContent = ''; logDiagnosticHeader(); }); }
  { const b = $('btn-copy-log'); if (b) b.addEventListener('click', () => navigator.clipboard.writeText(logText()).then(() => logSys('log copied')).catch(() => {})); }
  { const b = $('btn-save-log'); if (b) b.addEventListener('click', saveLog); }

  updateShortcuts();
  parseDeepLink();
  if (pendingDeepAction) { logSys(t('scPending')); tryAutoReconnect(); }
});
