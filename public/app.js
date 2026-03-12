/* ──────────────────────────────────────────────────────────────
   Vault — UI Controller
   All crypto via engine.js (CryptoEngine)
   Large content guard: outputs > 20MB are not rendered in DOM,
   only offered as direct download.
─────────────────────────────────────────────────────────────── */
const E = CryptoEngine;

const DISPLAY_LIMIT = 20 * 1024 * 1024; // 20 MB

const cfg = {
  autoClear: true,
  charCount: true,
  stego: true,
  chunks: true,
};

/* ── Helpers ─────────────────────────────────────────────────────── */
const $  = id => document.getElementById(id);
const show = (el, cls = 'visible') => el.classList.add(cls);
const hide = (el, cls = 'visible') => el.classList.remove(cls);

function setStatus(el, msg, type = 'info') {
  el.textContent = (type === 'ok' ? '✓ ' : type === 'err' ? '✗ ' : 'ℹ ') + msg;
  el.className = `status visible ${type}`;
}
function clearStatus(el) { el.className = 'status'; }

function showProgress(wrap, fill, pct) {
  wrap.style.display = 'block';
  fill.style.width = pct + '%';
}
function hideProgress(wrap) { wrap.style.display = 'none'; }

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer ?? buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBuf(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s/g, '');
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2)
    arr[i / 2] = parseInt(clean.substr(i, 2), 16);
  return arr;
}

let clipTimeout = null;
async function copyToClip(text) {
  try {
    await navigator.clipboard.writeText(text);
    if (cfg.autoClear) {
      clearTimeout(clipTimeout);
      clipTimeout = setTimeout(() => {
        navigator.clipboard.writeText('').catch(() => {});
      }, 30000);
    }
    return true;
  } catch { return false; }
}

function updateStrength(pw, fillId, labelId) {
  const score = E.scorePassword(pw);
  const fill  = $(fillId);
  const label = $(labelId);
  fill.style.width = score + '%';
  const levels = [
    [80, '🟢 STRONG',    '#00e676'],
    [50, '🟡 MODERATE',  '#ffd740'],
    [20, '🟠 WEAK',      '#ff9100'],
    [0,  '🔴 VERY WEAK', '#ff3d71'],
  ];
  const [, lbl, col] = levels.find(([t]) => score >= t) || levels[3];
  fill.style.background = col;
  label.textContent = pw ? `strength: ${lbl} (${score}/100)` : 'strength: —';
}

/**
 * Render output text into a .stego-out box.
 * If content exceeds DISPLAY_LIMIT bytes, show a warning instead and offer download.
 *
 * @param {HTMLElement} boxEl   - the .stego-out / .output-box element
 * @param {string}      text    - the string to display
 * @param {string}      [dlName] - filename for the download fallback
 * @param {HTMLElement} [countEl] - optional element to receive char count
 */
function renderOutput(boxEl, text, dlName = 'output.txt', countEl = null) {
  const byteLen = new TextEncoder().encode(text).length;

  if (byteLen > DISPLAY_LIMIT) {
    // Too large — show warning, offer download only
    boxEl.innerHTML = `
      <div class="large-content-warning">
        <span class="warn-icon">⚠</span>
        <div>
          <div>Content too large to display (${(byteLen / 1024 / 1024).toFixed(2)} MB — limit 20 MB).</div>
          <div class="warn-size">Use the Export button to download the file directly.</div>
        </div>
      </div>`;
    if (countEl) countEl.textContent = `(${(byteLen / 1024 / 1024).toFixed(2)} MB — download only)`;
    return false; // caller should force-download
  }

  boxEl.textContent = text;
  if (countEl && cfg.charCount) {
    countEl.textContent = `(${text.length.toLocaleString()} chars, ${byteLen.toLocaleString()} bytes)`;
  }
  return true;
}

/* ── Drop zone setup ──────────────────────────────────────────────── */
function setupDrop(zoneId, inputId, nameId, onFile) {
  const zone  = $(zoneId);
  const input = $(inputId);
  if (!zone || !input) return;

  input.addEventListener('change', () => {
    if (!input.files.length) return;
    if (nameId) $(nameId).textContent = [...input.files].map(f => f.name).join(', ');
    onFile(input.files);
  });

  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    if (!e.dataTransfer.files.length) return;
    if (nameId) $(nameId).textContent = [...e.dataTransfer.files].map(f => f.name).join(', ');
    onFile(e.dataTransfer.files);
  });
}

/* ── Generic encrypt/decrypt for file tabs ────────────────────────── */
async function encryptFile(file, pw, statusEl, progressWrap, progressFill) {
  if (!file) return setStatus(statusEl, 'No file selected', 'err');
  if (!pw)   return setStatus(statusEl, 'Enter a passphrase', 'err');

  showProgress(progressWrap, progressFill, 10);
  setStatus(statusEl, 'Reading file…', 'info');

  try {
    const bytes = await E.fileToBytes(file);
    showProgress(progressWrap, progressFill, 40);
    setStatus(statusEl, 'Encrypting (AES-256-GCM)…', 'info');

    const packed = await E.encryptBytes(bytes, pw, file.name, file.type || 'application/octet-stream');
    showProgress(progressWrap, progressFill, 90);

    const outName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_') + '.vlt';
    E.downloadBytes(packed, outName);
    showProgress(progressWrap, progressFill, 100);
    setStatus(statusEl, `Encrypted → ${outName} (${(packed.byteLength / 1024 / 1024).toFixed(2)} MB)`, 'ok');
  } catch (e) {
    setStatus(statusEl, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(progressWrap), 1500);
  }
}

async function decryptFile(file, pw, statusEl, progressWrap, progressFill) {
  if (!file) return setStatus(statusEl, 'No file selected', 'err');
  if (!pw)   return setStatus(statusEl, 'Enter a passphrase', 'err');

  showProgress(progressWrap, progressFill, 10);
  setStatus(statusEl, 'Reading encrypted file…', 'info');

  try {
    const bytes = await E.fileToBytes(file);
    showProgress(progressWrap, progressFill, 40);
    setStatus(statusEl, 'Decrypting…', 'info');

    const { data, filename, mime } = await E.decryptBytes(bytes, pw);
    showProgress(progressWrap, progressFill, 90);
    E.downloadBytes(data, filename || 'decrypted', mime);
    showProgress(progressWrap, progressFill, 100);
    setStatus(statusEl, `Decrypted → ${filename} (${(data.byteLength / 1024 / 1024).toFixed(2)} MB)`, 'ok');
  } catch (e) {
    setStatus(statusEl, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(progressWrap), 1500);
  }
}

/* ══════════════════════════════════════════════════════════════════
   TABS
══════════════════════════════════════════════════════════════════ */
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).classList.add('active');
  });
});

/* ── Password toggles ─────────────────────────────────────────────── */
document.querySelectorAll('.pw-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const inp = $(btn.dataset.target);
    inp.type = inp.type === 'password' ? 'text' : 'password';
    btn.textContent = inp.type === 'password' ? '👁' : '🙈';
  });
});

/* ── Strength meters ──────────────────────────────────────────────── */
[
  ['txt-pw',    'txt-strength-fill',    'txt-strength-label'],
  ['file-pw',   'file-strength-fill',   'file-strength-label'],
  ['zip-pw',    'zip-strength-fill',    'zip-strength-label'],
  ['folder-pw', 'folder-strength-fill', 'folder-strength-label'],
  ['bin-pw',    'bin-strength-fill',    'bin-strength-label'],
].forEach(([pwId, fId, lId]) => {
  $(pwId)?.addEventListener('input', e => updateStrength(e.target.value, fId, lId));
});

/* ══════════════════════════════════════════════════════════════════
   TEXT TAB
══════════════════════════════════════════════════════════════════ */
let txtEncryptedOutput = '';

$('txt-encrypt-btn').addEventListener('click', async () => {
  const pw    = $('txt-pw').value;
  const plain = $('txt-plain').value;
  const cover = $('txt-cover').value;
  const st    = $('txt-status');

  if (!pw)    return setStatus(st, 'Enter a passphrase', 'err');
  if (!plain) return setStatus(st, 'Enter text to encrypt', 'err');

  const pw2 = $('txt-progress'), pf = $('txt-progress-fill');
  showProgress(pw2, pf, 20);
  setStatus(st, 'Encrypting…', 'info');

  try {
    const bytes = new TextEncoder().encode(plain);
    showProgress(pw2, pf, 50);

    let output;
    if (cfg.stego) {
      output = await E.encryptToStego(bytes, pw, cover, 'message.txt', 'text/plain');
    } else {
      const packed = await E.encryptBytes(bytes, pw, 'message.txt', 'text/plain');
      const b64 = bufToBase64(packed);
      output = cover ? cover + '\n\n' + b64 : b64;
    }

    showProgress(pw2, pf, 100);
    txtEncryptedOutput = output;

    const didRender = renderOutput($('txt-output'), output, 'encrypted.txt', $('txt-out-chars'));
    if (!didRender) {
      // Auto-download if too large to display
      E.downloadText(output, 'encrypted.txt');
      setStatus(st, 'Encrypted — content too large to display, auto-downloaded as encrypted.txt', 'ok');
    } else {
      setStatus(st, 'Encrypted successfully', 'ok');
    }
  } catch (e) {
    setStatus(st, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(pw2), 1200);
  }
});

$('txt-decrypt-btn').addEventListener('click', async () => {
  const pw    = $('txt-pw').value;
  const input = $('txt-plain').value || txtEncryptedOutput;
  const st    = $('txt-status');

  if (!pw)    return setStatus(st, 'Enter a passphrase', 'err');
  if (!input) return setStatus(st, 'No encrypted text to decrypt', 'err');

  const pw2 = $('txt-progress'), pf = $('txt-progress-fill');
  showProgress(pw2, pf, 20);
  setStatus(st, 'Decrypting…', 'info');

  try {
    let data, filename;
    if (cfg.stego) {
      ({ data, filename } = await E.decryptFromStego(input, pw));
    } else {
      const packed = base64ToBuf(input.trim().split('\n\n').pop());
      ({ data, filename } = await E.decryptBytes(packed, pw));
    }

    const decoded = new TextDecoder().decode(data);
    showProgress(pw2, pf, 100);

    const didRender = renderOutput($('txt-output'), decoded, filename || 'decrypted.txt', $('txt-out-chars'));
    if (!didRender) {
      E.downloadText(decoded, filename || 'decrypted.txt');
      setStatus(st, 'Decrypted — content too large to display, auto-downloaded', 'ok');
    } else {
      setStatus(st, 'Decrypted successfully', 'ok');
    }
  } catch (e) {
    setStatus(st, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(pw2), 1200);
  }
});

$('txt-clear-btn').addEventListener('click', () => {
  $('txt-plain').value = '';
  $('txt-cover').value = '';
  $('txt-output').innerHTML = '<span class="output-placeholder">Encrypted stego text will appear here…</span>';
  txtEncryptedOutput = '';
  $('txt-out-chars').textContent = '';
  clearStatus($('txt-status'));
});

$('txt-copy-btn').addEventListener('click', async () => {
  if (!txtEncryptedOutput) return;
  const ok = await copyToClip(txtEncryptedOutput);
  setStatus($('txt-status'),
    ok ? 'Copied to clipboard' + (cfg.autoClear ? ' (auto-clears in 30s)' : '') : 'Clipboard access denied',
    ok ? 'ok' : 'err');
});

$('txt-export-btn').addEventListener('click', () => {
  if (!txtEncryptedOutput) return;
  E.downloadText(txtEncryptedOutput, 'encrypted.txt');
});

$('txt-import-btn').addEventListener('click', () => $('txt-import-file').click());
$('txt-import-file').addEventListener('change', async e => {
  const file = e.target.files[0]; if (!file) return;
  const text = await file.text();
  $('txt-plain').value = text;
  setStatus($('txt-status'), `Loaded: ${file.name}`, 'info');
});

$('txt-paste-btn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) return setStatus($('txt-status'), 'Clipboard empty', 'err');
    $('txt-plain').value = text;
    setStatus($('txt-status'), 'Pasted from clipboard — press Decrypt', 'info');
  } catch {
    setStatus($('txt-status'), 'Clipboard read denied — paste manually into the Plaintext box', 'err');
  }
});

/* ══════════════════════════════════════════════════════════════════
   FILE TAB
══════════════════════════════════════════════════════════════════ */
let fileEncFile = null, fileDecFile = null;

setupDrop('file-drop-enc', 'file-input-enc', 'file-enc-name', files => { fileEncFile = files[0]; });
setupDrop('file-drop-dec', 'file-input-dec', 'file-dec-name', files => { fileDecFile = files[0]; });

$('file-encrypt-btn').addEventListener('click', () =>
  encryptFile(fileEncFile, $('file-pw').value, $('file-status'), $('file-progress'), $('file-progress-fill'))
);
$('file-decrypt-btn').addEventListener('click', () =>
  decryptFile(fileDecFile, $('file-pw').value, $('file-status'), $('file-progress'), $('file-progress-fill'))
);

/* ══════════════════════════════════════════════════════════════════
   ZIP TAB
══════════════════════════════════════════════════════════════════ */
let zipEncFile = null, zipDecFile = null;

setupDrop('zip-drop-enc', 'zip-input-enc', 'zip-enc-name', files => { zipEncFile = files[0]; });
setupDrop('zip-drop-dec', 'zip-input-dec', 'zip-dec-name', files => { zipDecFile = files[0]; });

$('zip-encrypt-btn').addEventListener('click', () =>
  encryptFile(zipEncFile, $('zip-pw').value, $('zip-status'), $('zip-progress'), $('zip-progress-fill'))
);
$('zip-decrypt-btn').addEventListener('click', () =>
  decryptFile(zipDecFile, $('zip-pw').value, $('zip-status'), $('zip-progress'), $('zip-progress-fill'))
);

/* ══════════════════════════════════════════════════════════════════
   FOLDER TAB — VLT Bundle format
   [4B "VLTB"][4B count][foreach: [4B nameLen][name][4B mimeLen][mime][8B dataLen][data]]
══════════════════════════════════════════════════════════════════ */
let folderFiles = null, folderDecFile = null;

function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; }
function readU32(buf, off) { return new DataView(buf).getUint32(off, false); }
function readU64(buf, off) { return Number(new DataView(buf).getBigUint64(off, false)); }

setupDrop('folder-drop', 'folder-input', 'folder-name', files => {
  folderFiles = [...files];
  const list  = $('folder-file-list');
  const items = $('folder-file-items');
  list.style.display = 'block';
  items.innerHTML = folderFiles.map(f =>
    `<div style="padding:2px 0;border-bottom:1px solid var(--border)">📄 ${f.webkitRelativePath || f.name} <span style="color:var(--text3)">(${(f.size / 1024).toFixed(1)} KB)</span></div>`
  ).join('');
  $('folder-name').textContent = `${folderFiles.length} files selected`;
});

setupDrop('folder-drop-dec', 'folder-input-dec', 'folder-dec-name', files => { folderDecFile = files[0]; });

$('folder-encrypt-btn').addEventListener('click', async () => {
  const pw = $('folder-pw').value;
  const st = $('folder-status');
  const pw2 = $('folder-progress'), pf = $('folder-progress-fill');

  if (!folderFiles?.length) return setStatus(st, 'No folder selected', 'err');
  if (!pw)                  return setStatus(st, 'Enter a passphrase', 'err');

  showProgress(pw2, pf, 5);
  setStatus(st, 'Building bundle…', 'info');

  try {
    const enc   = new TextEncoder();
    const MAGIC = new Uint8Array([0x56, 0x4C, 0x54, 0x42]); // "VLTB"
    const parts = [MAGIC, u32(folderFiles.length)];

    for (let i = 0; i < folderFiles.length; i++) {
      const f    = folderFiles[i];
      const name = enc.encode(f.webkitRelativePath || f.name);
      const mime = enc.encode(f.type || 'application/octet-stream');
      const data = await E.fileToBytes(f);
      parts.push(u32(name.length), name, u32(mime.length), mime, u64(data.byteLength), data);
      showProgress(pw2, pf, 5 + Math.floor(70 * (i + 1) / folderFiles.length));
    }

    const totalLen = parts.reduce((s, p) => s + p.byteLength, 0);
    const bundle   = new Uint8Array(totalLen);
    let off = 0;
    for (const p of parts) { bundle.set(p, off); off += p.byteLength; }

    setStatus(st, 'Encrypting bundle…', 'info');
    showProgress(pw2, pf, 80);
    const packed = await E.encryptBytes(bundle, pw, 'folder.vltb', 'application/vnd.vault.bundle');
    showProgress(pw2, pf, 100);
    E.downloadBytes(packed, 'folder_bundle.vlt');
    setStatus(st, `Encrypted ${folderFiles.length} files → folder_bundle.vlt`, 'ok');
  } catch (e) {
    setStatus(st, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(pw2), 1500);
  }
});

$('folder-decrypt-btn').addEventListener('click', async () => {
  const pw = $('folder-pw').value;
  const st = $('folder-status');
  const pw2 = $('folder-progress'), pf = $('folder-progress-fill');

  if (!folderDecFile) return setStatus(st, 'No bundle file selected', 'err');
  if (!pw)            return setStatus(st, 'Enter a passphrase', 'err');

  showProgress(pw2, pf, 10);
  setStatus(st, 'Decrypting bundle…', 'info');

  try {
    const raw         = await E.fileToBytes(folderDecFile);
    const { data }    = await E.decryptBytes(raw, pw);
    showProgress(pw2, pf, 60);

    const buf   = data.buffer;
    const magic = new Uint8Array(buf, 0, 4);
    if (magic[0] !== 0x56 || magic[1] !== 0x4C || magic[2] !== 0x54 || magic[3] !== 0x42)
      throw new Error('Not a valid folder bundle (wrong magic bytes)');

    const count = readU32(buf, 4);
    let off = 8;
    const dec = new TextDecoder();
    setStatus(st, `Extracting ${count} files…`, 'info');

    for (let i = 0; i < count; i++) {
      const nameLen = readU32(buf, off); off += 4;
      const name    = dec.decode(new Uint8Array(buf, off, nameLen)); off += nameLen;
      const mimeLen = readU32(buf, off); off += 4;
      const mime    = dec.decode(new Uint8Array(buf, off, mimeLen)); off += mimeLen;
      const dataLen = readU64(buf, off); off += 8;
      const fileData = new Uint8Array(buf, off, dataLen); off += dataLen;
      // Stagger downloads so browser doesn't block them
      await new Promise(r => setTimeout(r, 60 * i));
      E.downloadBytes(fileData, name.split('/').pop(), mime);
      showProgress(pw2, pf, 60 + Math.floor(40 * (i + 1) / count));
    }

    setStatus(st, `Extracted ${count} files successfully`, 'ok');
  } catch (e) {
    setStatus(st, e.message, 'err');
  } finally {
    setTimeout(() => hideProgress(pw2), 1500);
  }
});

/* ══════════════════════════════════════════════════════════════════
   BINARY TAB
══════════════════════════════════════════════════════════════════ */
let binOutput = null;

async function parseBinInput() {
  const val = $('bin-input').value.trim();
  const fmt = $('bin-format').value;
  if (!val) throw new Error('No input data');
  if (fmt === 'hex')    return hexToBytes(val);
  if (fmt === 'base64') return base64ToBuf(val);
  return new TextEncoder().encode(val);
}

$('bin-encrypt-btn').addEventListener('click', async () => {
  const pw  = $('bin-pw').value;
  const st  = $('bin-status');
  const pw2 = $('bin-progress'), pf = $('bin-progress-fill');
  if (!pw) return setStatus(st, 'Enter a passphrase', 'err');

  showProgress(pw2, pf, 20);
  try {
    const bytes  = await parseBinInput();
    showProgress(pw2, pf, 50);
    const packed = await E.encryptBytes(bytes, pw, 'binary.bin', 'application/octet-stream');
    showProgress(pw2, pf, 80);

    const outFmt = $('bin-out-format').value;
    const packedArr = new Uint8Array(packed.buffer ?? packed);
    let outputText;
    if (outFmt === 'hex')    outputText = [...packedArr].map(b => b.toString(16).padStart(2, '0')).join('');
    else if (outFmt === 'base64') outputText = bufToBase64(packedArr);
    else                     outputText = E.bytesToStego(packedArr);

    binOutput = { text: outputText, bytes: packedArr };

    const didRender = renderOutput($('bin-output'), outputText, 'encrypted.bin');
    if (!didRender) E.downloadBytes(packedArr, 'encrypted.bin');
    showProgress(pw2, pf, 100);
    setStatus(st, `Encrypted — ${(packedArr.byteLength / 1024).toFixed(1)} KB`, 'ok');
  } catch (e) { setStatus(st, e.message, 'err'); }
  finally { setTimeout(() => hideProgress(pw2), 1200); }
});

$('bin-decrypt-btn').addEventListener('click', async () => {
  const pw  = $('bin-pw').value;
  const st  = $('bin-status');
  const pw2 = $('bin-progress'), pf = $('bin-progress-fill');
  if (!pw) return setStatus(st, 'Enter a passphrase', 'err');

  showProgress(pw2, pf, 20);
  try {
    const val = $('bin-input').value.trim();
    const fmt = $('bin-format').value;
    let packed;
    if (fmt === 'hex')    packed = hexToBytes(val);
    else if (fmt === 'base64') packed = base64ToBuf(val);
    else                  packed = E.stegoToBytes(val);

    showProgress(pw2, pf, 50);
    const { data, filename } = await E.decryptBytes(packed, pw);
    showProgress(pw2, pf, 80);

    const outFmt = $('bin-out-format').value;
    let outputText;
    if (outFmt === 'hex')    outputText = [...data].map(b => b.toString(16).padStart(2, '0')).join('');
    else if (outFmt === 'base64') outputText = bufToBase64(data);
    else                     outputText = new TextDecoder().decode(data);

    binOutput = { text: outputText, bytes: data };

    const didRender = renderOutput($('bin-output'), outputText, filename || 'decrypted.bin');
    if (!didRender) E.downloadBytes(data, filename || 'decrypted.bin');
    showProgress(pw2, pf, 100);
    setStatus(st, `Decrypted — ${filename}`, 'ok');
  } catch (e) { setStatus(st, e.message, 'err'); }
  finally { setTimeout(() => hideProgress(pw2), 1200); }
});

$('bin-copy-btn').addEventListener('click', async () => {
  if (!binOutput) return;
  const ok = await copyToClip(binOutput.text);
  setStatus($('bin-status'), ok ? 'Copied' : 'Copy failed', ok ? 'ok' : 'err');
});

$('bin-export-btn').addEventListener('click', () => {
  if (!binOutput?.bytes) return;
  E.downloadBytes(binOutput.bytes, 'output.bin');
});

/* ══════════════════════════════════════════════════════════════════
   TOOLS TAB
══════════════════════════════════════════════════════════════════ */

/* ── Password generator ───────────────────────────────────────────── */
const WORDLIST = [
  'alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel',
  'india','juliet','kilo','lima','mike','november','oscar','papa',
  'quebec','romeo','sierra','tango','uniform','victor','whiskey','xray',
  'yankee','zulu','amber','blaze','cipher','ember','forge','ghost',
  'haven','iron','jade','knight','lunar','mesa','nova','onyx',
  'prism','quartz','raven','slate','titan','ultra','vault','warden',
  'xenon','yield','zenith','arctic','breach','comet','drift','eagle',
  'flint','grain','hydra','input','judge','karma','lance','magic',
  'north','orbit','phase','relay','shade','trace','union','vortex',
];

$('gen-btn').addEventListener('click', () => {
  const len  = Math.max(4, parseInt($('gen-len').value) || 24);
  const mode = $('gen-mode').value;
  let pw = '';

  if (mode === 'random') {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*-_=+';
    const arr   = crypto.getRandomValues(new Uint8Array(len));
    pw = [...arr].map(b => chars[b % chars.length]).join('');
  } else if (mode === 'words') {
    const wordCount = Math.max(3, Math.ceil(len / 5));
    const arr = crypto.getRandomValues(new Uint16Array(wordCount));
    pw = [...arr].map(n => WORDLIST[n % WORDLIST.length]).join('-');
  } else {
    const arr = crypto.getRandomValues(new Uint8Array(len));
    pw = [...arr].map(b => (b % 10).toString()).join('');
  }

  $('gen-output').textContent = pw;
  updateStrength(pw, 'gen-strength-fill', 'gen-strength-label');
});

$('gen-copy-btn').addEventListener('click', async () => {
  const pw = $('gen-output').textContent;
  if (pw.includes('appears here')) return;
  const ok = await copyToClip(pw);
  setStatus($('tools-status'), ok ? 'Password copied' : 'Copy failed', ok ? 'ok' : 'err');
});

/* ── Hash utility ─────────────────────────────────────────────────── */
$('hash-btn').addEventListener('click', async () => {
  const input = $('hash-input').value;
  const algo  = $('hash-algo').value;
  if (!input) return;
  try {
    const data = new TextEncoder().encode(input);
    const buf  = await crypto.subtle.digest(algo, data);
    const hex  = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    $('hash-output').textContent = hex;
    setStatus($('tools-status'), `${algo} hash computed`, 'ok');
  } catch (e) { setStatus($('tools-status'), e.message, 'err'); }
});

$('hash-copy-btn').addEventListener('click', async () => {
  const h = $('hash-output').textContent;
  if (h.includes('output')) return;
  await copyToClip(h);
  setStatus($('tools-status'), 'Hash copied', 'ok');
});

/* ── Key export / import ──────────────────────────────────────────── */
$('key-export-btn').addEventListener('click', async () => {
  const pw = $('key-export-pw').value;
  if (!pw) return setStatus($('tools-status'), 'Enter a passphrase to export', 'err');
  try {
    const enc    = new TextEncoder().encode(pw);
    const packed = await E.encryptBytes(enc, pw + '_keyexport', 'passphrase.key', 'text/plain');
    E.downloadBytes(packed, 'vault.vkey');
    setStatus($('tools-status'), 'Key file exported → vault.vkey', 'ok');
  } catch (e) { setStatus($('tools-status'), e.message, 'err'); }
});

$('key-import-btn').addEventListener('click', async () => {
  const file = $('key-import-file').files[0];
  if (!file) return setStatus($('tools-status'), 'No key file selected', 'err');
  const userPw = prompt('Enter the passphrase to unlock this key file:');
  if (!userPw) return;
  try {
    const bytes      = await E.fileToBytes(file);
    const { data }   = await E.decryptBytes(bytes, userPw + '_keyexport');
    const recovered  = new TextDecoder().decode(data);
    $('key-import-out').style.display = 'block';
    $('key-import-val').textContent = recovered;
    setStatus($('tools-status'), 'Key imported successfully', 'ok');
  } catch (e) { setStatus($('tools-status'), 'Failed: ' + e.message, 'err'); }
});

setupDrop('key-import-file', 'key-import-file', 'key-import-name', () => {});

/* ══════════════════════════════════════════════════════════════════
   CONFIG TAB
══════════════════════════════════════════════════════════════════ */
$('cfg-auto-clear').addEventListener('change', e => { cfg.autoClear = e.target.checked; });
$('cfg-char-count').addEventListener('change', e => { cfg.charCount = e.target.checked; });
$('cfg-stego').addEventListener('change',      e => { cfg.stego     = e.target.checked; });
$('cfg-chunks').addEventListener('change',     e => { cfg.chunks    = e.target.checked; });
