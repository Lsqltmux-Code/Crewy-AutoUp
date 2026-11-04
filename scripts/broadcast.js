const https = require('https');

const TG_BOT_TOKEN = '9269865623:AAF3DdIUWoL6W_zvRpjzFVngaXvV32sqvow';
const LIST_URL = 'https://raw.githubusercontent.com/Lsqltmux-Code/Crewy-AutoUp/main/broadcast-list.json';

const version = process.argv[2] || '0.0.0';
const message = process.argv[3] || 'update sc';

function fetchJson(url) {
  return new Promise((resolve) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (_) { resolve({ chats: [] }); }
      });
    }).on('error', () => resolve({ chats: [] }));
  });
}

function sendTo(chatId, text) {
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
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          resolve({ ok: j.ok, desc: j.description });
        } catch (_) {
          resolve({ ok: false });
        }
      });
    });
    req.on('error', (e) => resolve({ ok: false, desc: e.message }));
    req.write(payload);
    req.end();
  });
}

function buildPremium(title, lines) {
  const border = '━━━━━━━━━━━━━━━━━━━━━━━━';
  const body = lines.map((l) => `${l.label.padEnd(8)} : ${l.value}`).join('\n');
  return `${border}\n  ${title}\n${border}\n` +
    '```js\n' + body + '\n```\n' +
    `${border}\n  𝑪͒𝒓͢𝒆͠𝒘͒𝒚͢ 𝑰͠𝒏͒𝒇͢𝒊͠𝒏͒𝒊͢𝒕͠𝒚 v${version}\n${border}`;
}

async function main() {
  const list = await fetchJson(LIST_URL);
  const chats = list.chats || [];
  if (!chats.length) {
    console.log('⚠️  broadcast-list.json kosong atau gagal di-fetch.');
    return;
  }
  const text = buildPremium('📢 UPDATE TERSEDIA', [
    { label: 'Versi', value: version },
    { label: 'Pesan', value: message },
    { label: 'Waktu', value: new Date().toISOString() },
  ]);
  console.log(`📢 Broadcast ke ${chats.length} chat...`);
  for (const chatId of chats) {
    const res = await sendTo(chatId, text);
    console.log(res.ok ? `✅ ${chatId}` : `❌ ${chatId} — ${res.desc || 'gagal'}`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log('🎉 Broadcast selesai.');
}

main();