#!/bin/bash
set -e

MSG="${1:-update sc}"

CURRENT=$(grep "const SC_VERSION = '" index.js | sed "s/.*'\(.*\)'.*/\1/")
NEW=$(node -p "const v='$CURRENT'.split('.').map(Number); v[2]++; v.join('.')")

sed -i "s/const SC_VERSION = '.*'/const SC_VERSION = '$NEW'/" index.js

echo "📦 Versi: $CURRENT → $NEW"

node -e "
const fs = require('fs');
const crypto = require('crypto');
const files = ['index.js', 'package.json'];
const hashes = files.map(f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'));
fs.writeFileSync('.integrity', JSON.stringify(hashes, null, 2));
console.log('✅ .integrity regenerated');
"

git add -A
git commit -m "v$NEW — $MSG" || echo "Tidak Ada Perubahan."
git push origin main

echo "✅ Push selesai."