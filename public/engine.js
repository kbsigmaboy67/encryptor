/**
 * CryptoEngine - Military-grade AES-256-GCM encryption with steganographic output
 * Uses Unicode invisible/zero-width characters for minimal visible footprint
 * All crypto operations run in-browser via Web Crypto API (no server round-trips)
 */

const CryptoEngine = (() => {
  'use strict';

  // ── Steganography alphabet ──────────────────────────────────────────────────
  // 256 visually-invisible Unicode codepoints mapped to byte values 0–255
  // Sources: zero-width chars, variation selectors, tags block, combining marks
  const STEGO_ALPHABET = (() => {
    const chars = [];
    // Zero-width / invisible separators (0x00–0x0F → 16 chars)
    const base = [
      '\u200B', // ZERO WIDTH SPACE
      '\u200C', // ZERO WIDTH NON-JOINER
      '\u200D', // ZERO WIDTH JOINER
      '\u2060', // WORD JOINER
      '\u2061', // FUNCTION APPLICATION
      '\u2062', // INVISIBLE TIMES
      '\u2063', // INVISIBLE SEPARATOR
      '\u2064', // INVISIBLE PLUS
      '\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM)
      '\u180E', // MONGOLIAN VOWEL SEPARATOR
      '\u200E', // LEFT-TO-RIGHT MARK
      '\u200F', // RIGHT-TO-LEFT MARK
      '\u202A', // LEFT-TO-RIGHT EMBEDDING
      '\u202B', // RIGHT-TO-LEFT EMBEDDING
      '\u202C', // POP DIRECTIONAL FORMATTING
      '\u202D', // LEFT-TO-RIGHT OVERRIDE
    ];
    chars.push(...base); // 16 chars

    // Unicode Tags block U+E0000–U+E007F (128 chars, fully invisible)
    for (let i = 0; i <= 127; i++) {
      chars.push(String.fromCodePoint(0xE0000 + i));
    }
    // Variation selectors supplement U+E0100–U+E01EF (240 chars, pick 112 to reach 256)
    for (let i = 0; i < 112; i++) {
      chars.push(String.fromCodePoint(0xE0100 + i));
    }
    return chars; // exactly 256 entries
  })();

  // Reverse lookup map: char → byte value
  const STEGO_MAP = new Map(STEGO_ALPHABET.map((ch, i) => [ch, i]));

  // Delimiter between cover text and payload (invisible)
  const DELIM = '\u{E007F}'; // TAG DELETE (completely invisible)

  // ── Utility ─────────────────────────────────────────────────────────────────

  function bytesToStego(bytes) {
    let out = '';
    for (const b of bytes) out += STEGO_ALPHABET[b];
    return out;
  }

  function stegoToBytes(str) {
    const bytes = [];
    // Must iterate by code point (surrogate pairs for supplementary chars)
    for (const ch of str) {
      const val = STEGO_MAP.get(ch);
      if (val !== undefined) bytes.push(val);
    }
    return new Uint8Array(bytes);
  }

  function bufToHex(buf) {
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBuf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2)
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  function concatBuffers(...bufs) {
    const total = bufs.reduce((n, b) => n + b.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const b of bufs) { out.set(new Uint8Array(b), offset); offset += b.byteLength; }
    return out.buffer;
  }

  // ── Key Derivation (PBKDF2 → AES-256-GCM) ──────────────────────────────────

  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── Encryption ──────────────────────────────────────────────────────────────

  /**
   * Encrypt arbitrary bytes with a password.
   * Returns: { ciphertext: Uint8Array, meta: { salt, iv, originalName, originalSize, mime } }
   * Wire format: [4B magic][12B iv][32B salt][4B nameLen][nameBytes][dataBytes][16B auth tag implicit]
   */
  async function encryptBytes(plainBytes, password, filename = '', mime = 'application/octet-stream') {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKey(password, salt);

    // Prepend a small JSON header to plaintext so we recover filename+mime
    const enc = new TextEncoder();
    const header = enc.encode(JSON.stringify({ n: filename, m: mime }) + '\x00');
    const payload = concatBuffers(header.buffer, plainBytes.buffer ?? plainBytes);

    const cipherData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key, payload
    );

    // Pack: MAGIC(4) + IV(12) + SALT(32) + cipherData
    const MAGIC = new Uint8Array([0x56, 0x4C, 0x54, 0x01]); // "VLT\x01"
    const packed = new Uint8Array(concatBuffers(MAGIC.buffer, iv.buffer, salt.buffer, cipherData));
    return packed;
  }

  /**
   * Decrypt bytes previously produced by encryptBytes.
   * Returns: { data: Uint8Array, filename: string, mime: string }
   */
  async function decryptBytes(packedBytes, password) {
    const buf = new Uint8Array(packedBytes);
    // Validate magic
    if (buf[0] !== 0x56 || buf[1] !== 0x4C || buf[2] !== 0x54 || buf[3] !== 0x01)
      throw new Error('Invalid encrypted data (bad magic bytes)');

    const iv   = buf.slice(4, 16);
    const salt = buf.slice(16, 48);
    const cipherData = buf.slice(48);

    const key = await deriveKey(password, salt);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, cipherData);
    } catch {
      throw new Error('Decryption failed — wrong password or corrupted data');
    }

    const dec = new TextDecoder();
    const plainArr = new Uint8Array(plain);
    // Find null terminator for header
    let headerEnd = plainArr.indexOf(0);
    if (headerEnd === -1) throw new Error('Corrupted payload header');
    const headerStr = dec.decode(plainArr.slice(0, headerEnd));
    let meta = { n: 'decrypted', m: 'application/octet-stream' };
    try { meta = JSON.parse(headerStr); } catch {}
    const data = plainArr.slice(headerEnd + 1);
    return { data, filename: meta.n || 'decrypted', mime: meta.m || 'application/octet-stream' };
  }

  // ── Steganography wrappers ──────────────────────────────────────────────────

  async function encryptToStego(plainBytes, password, coverText = '', filename = '', mime = '') {
    const packed = await encryptBytes(plainBytes, password, filename, mime);
    const stego  = bytesToStego(packed);
    return coverText ? coverText + DELIM + stego : stego;
  }

  async function decryptFromStego(stegoText, password) {
    // Strip cover text if delimiter present
    const delimIdx = stegoText.indexOf(DELIM);
    const payload  = delimIdx >= 0 ? stegoText.slice(delimIdx + DELIM.length) : stegoText;
    const packed   = stegoToBytes(payload);
    if (packed.length === 0) throw new Error('No encrypted payload found in text');
    return decryptBytes(packed, password);
  }

  // ── File helpers ─────────────────────────────────────────────────────────────

  async function fileToBytes(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(new Uint8Array(e.target.result));
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  function downloadText(text, filename) {
    downloadBlob(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);
  }

  function downloadBytes(bytes, filename, mime = 'application/octet-stream') {
    downloadBlob(new Blob([bytes], { type: mime }), filename);
  }

  // ── Password strength ────────────────────────────────────────────────────────

  function scorePassword(pw) {
    let score = 0;
    if (!pw) return 0;
    if (pw.length >= 12) score += 20;
    if (pw.length >= 20) score += 20;
    if (/[a-z]/.test(pw)) score += 10;
    if (/[A-Z]/.test(pw)) score += 10;
    if (/\d/.test(pw))    score += 15;
    if (/[^a-zA-Z0-9]/.test(pw)) score += 25;
    return Math.min(score, 100);
  }

  // ── Export ──────────────────────────────────────────────────────────────────
  return {
    encryptToStego, decryptFromStego,
    encryptBytes, decryptBytes,
    bytesToStego, stegoToBytes,
    fileToBytes, downloadBlob, downloadText, downloadBytes,
    scorePassword,
    STEGO_ALPHABET, DELIM
  };
})();

window.CryptoEngine = CryptoEngine;
