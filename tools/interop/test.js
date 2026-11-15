const assert = require('assert');
const crypto = require('crypto');
const { CipherSuite, KemId, KdfId, AeadId } = require('hpke-js');

// --- Helpers ---
function toBase64URL(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64URL(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

function buildAAD(method, path, timestamp, nonceBuf) {
  const nonceHex = nonceBuf.toString('hex');
  const aadStr = `${method.toUpperCase()}|${path}|${timestamp}|${nonceHex}`;
  return Buffer.from(aadStr, 'utf8');
}

function computeFingerprint(rawKeyBuf) {
  const hash = crypto.createHash('sha256').update(rawKeyBuf).digest();
  return hash.subarray(0, 8).toString('hex').toUpperCase();
}

function ed25519PubFromRaw(raw) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
}

function ed25519PrivFromRaw(raw) {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'pkcs8' });
}

function packEnvelope(version, algorithm, enc, nonce, ciphertextAndTag) {
  return Buffer.concat([
    Buffer.from([version, algorithm]),
    enc,
    nonce,
    ciphertextAndTag
  ]);
}

function unpackEnvelope(buf) {
  if (buf.length < 62) {
    throw new Error(`Envelope buffer length ${buf.length} is less than minimum 62 bytes`);
  }
  const version = buf[0];
  const algorithm = buf[1];
  const enc = buf.subarray(2, 34);
  const nonce = buf.subarray(34, 46);
  const ciphertextAndTag = buf.subarray(46);
  return { version, algorithm, enc, nonce, ciphertextAndTag };
}

// --- Main Test Suite ---
async function runTests() {
  console.log('=== SideVault HPKE / Interop Test Suite (RFC 9180) ===\n');

  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305
  });

  // 1. Official RFC 9180 Appendix A.2 Vector Test
  console.log('[Test 1] RFC 9180 Appendix A.2 Vector Decryption...');
  {
    const skRaw = Buffer.from('8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb', 'hex');
    const enc = Buffer.from('1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a', 'hex');
    const info = Buffer.from('4f6465206f6e2061204772656369616e2055726e', 'hex');
    const expectedPt = 'Beauty is truth, truth beauty';

    // Sequence 0
    const aad0 = Buffer.from('436f756e742d30', 'hex');
    const ct0 = Buffer.from('1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28', 'hex');

    // Sequence 1
    const aad1 = Buffer.from('436f756e742d31', 'hex');
    const ct1 = Buffer.from('6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c', 'hex');

    const privateKey = await suite.importKey('raw', skRaw, false);
    const recipient = await suite.createRecipientContext({
      recipientKey: privateKey,
      enc: enc,
      info: info
    });

    const pt0 = await recipient.open(ct0, aad0);
    assert.strictEqual(new TextDecoder().decode(pt0), expectedPt, 'Seq 0 plaintext match');

    const pt1 = await recipient.open(ct1, aad1);
    assert.strictEqual(new TextDecoder().decode(pt1), expectedPt, 'Seq 1 plaintext match');
    console.log('  -> PASS: Verified against official RFC 9180 test vectors');
  }

  // 2. Envelope Serialization & Base64URL
  console.log('[Test 2] Envelope Serialization & Base64URL Encoding...');
  {
    const enc = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const ct = crypto.randomBytes(48); // 32B data + 16B tag
    const packed = packEnvelope(1, 1, enc, nonce, ct);
    assert.strictEqual(packed.length, 1 + 1 + 32 + 12 + 48);

    const b64url = toBase64URL(packed);
    const restored = fromBase64URL(b64url);
    assert.deepStrictEqual(packed, restored);

    const unpacked = unpackEnvelope(restored);
    assert.strictEqual(unpacked.version, 1);
    assert.strictEqual(unpacked.algorithm, 1);
    assert.deepStrictEqual(unpacked.enc, enc);
    assert.deepStrictEqual(unpacked.nonce, nonce);
    assert.deepStrictEqual(unpacked.ciphertextAndTag, ct);
    console.log('  -> PASS: Envelope packing, parsing and Base64URL codec verified');
  }

  // 3. Round-Trip Seal & Open with AAD
  console.log('[Test 3] End-to-End Seal and Open with AAD...');
  {
    const keyPair = await suite.generateKeyPair();
    const info = Buffer.from('SideVault-v1', 'utf8');
    const nonce = crypto.randomBytes(12);
    const timestamp = Math.floor(Date.now() / 1000);
    const aad = buildAAD('POST', '/api/v1/action', timestamp, nonce);
    const message = Buffer.from('Secure LAN communication from SideVault Node Client', 'utf8');

    // Sender seals
    const sender = await suite.createSenderContext({
      recipientPublicKey: keyPair.publicKey,
      info: info
    });
    const ciphertext = await sender.seal(message, aad);
    const enc = Buffer.from(sender.enc);

    // Pack into envelope
    const envelopeBuf = packEnvelope(1, 1, enc, nonce, Buffer.from(ciphertext));
    const envelopeB64URL = toBase64URL(envelopeBuf);

    // Recipient opens
    const parsed = unpackEnvelope(fromBase64URL(envelopeB64URL));
    const recipientAAD = buildAAD('POST', '/api/v1/action', timestamp, parsed.nonce);

    const recipient = await suite.createRecipientContext({
      recipientKey: keyPair.privateKey,
      enc: parsed.enc,
      info: info
    });
    const decrypted = await recipient.open(parsed.ciphertextAndTag, recipientAAD);

    assert.strictEqual(Buffer.from(decrypted).toString('utf8'), message.toString('utf8'));
    console.log('  -> PASS: Successfully sealed, transmitted via Base64URL, and opened');
  }

  // 4. Tampering Must Fail
  console.log('[Test 4] Tamper Resilience Check...');
  {
    const keyPair = await suite.generateKeyPair();
    const info = Buffer.from('SideVault-v1', 'utf8');
    const nonce = crypto.randomBytes(12);
    const aad = buildAAD('POST', '/api/v1/action', 1000, nonce);
    const message = Buffer.from('Confidential Instruction', 'utf8');

    const sender = await suite.createSenderContext({ recipientPublicKey: keyPair.publicKey, info });
    const ciphertext = Buffer.from(await sender.seal(message, aad));
    const enc = Buffer.from(sender.enc);

    // Tamper ciphertext
    const tamperedCT = Buffer.from(ciphertext);
    tamperedCT[0] ^= 0xFF;

    const recipient = await suite.createRecipientContext({ recipientKey: keyPair.privateKey, enc, info });
    let failed = false;
    try {
      await recipient.open(tamperedCT, aad);
    } catch {
      failed = true;
    }
    assert.strictEqual(failed, true, 'Opening tampered ciphertext must throw error');

    // Tamper AAD
    const tamperedAAD = buildAAD('POST', '/api/v1/malicious', 1000, nonce);
    const recipient2 = await suite.createRecipientContext({ recipientKey: keyPair.privateKey, enc, info });
    let aadFailed = false;
    try {
      await recipient2.open(ciphertext, tamperedAAD);
    } catch {
      aadFailed = true;
    }
    assert.strictEqual(aadFailed, true, 'Opening with tampered AAD must throw error');
    console.log('  -> PASS: Tampered ciphertext and tampered AAD both correctly rejected');
  }

  // 5. Ed25519 Signing & Fingerprint Interop
  console.log('[Test 5] Ed25519 Signing and Fingerprint Verification...');
  {
    const rawPriv = crypto.randomBytes(32);
    const privKey = ed25519PrivFromRaw(rawPriv);
    const pubKey = crypto.createPublicKey(privKey);

    // Export raw 32-byte public key
    const spki = pubKey.export({ format: 'der', type: 'spki' });
    const rawPub = spki.subarray(spki.length - 32);
    assert.strictEqual(rawPub.length, 32);

    const fp = computeFingerprint(rawPub);
    assert.strictEqual(fp.length, 16);

    const msg = Buffer.from('SideVault-Ed25519-Message-Integrity', 'utf8');
    const sig = crypto.sign(null, msg, privKey);
    assert.strictEqual(sig.length, 64);

    const valid = crypto.verify(null, msg, pubKey, sig);
    assert.strictEqual(valid, true);

    const invalid = crypto.verify(null, Buffer.from('tampered'), pubKey, sig);
    assert.strictEqual(invalid, false);
    console.log(`  -> PASS: Ed25519 64-byte signature verified (Fingerprint: ${fp})`);
  }

  // 6. Anti-Replay and Timestamp Window Simulation
  console.log('[Test 6] Anti-Replay & ±300s Timestamp Window Validation...');
  {
    const seenNonces = new Set();
    function checkReplayAndSkew(ts, nonceHex) {
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - ts) > 300) {
        throw new Error('Timestamp expired');
      }
      if (seenNonces.has(nonceHex)) {
        throw new Error('Replay detected');
      }
      seenNonces.add(nonceHex);
      return true;
    }

    const currentTs = Math.floor(Date.now() / 1000);
    const nonce1 = crypto.randomBytes(12).toString('hex');

    assert.strictEqual(checkReplayAndSkew(currentTs, nonce1), true);

    // Replay same nonce
    assert.throws(() => checkReplayAndSkew(currentTs, nonce1), /Replay detected/);

    // Expired timestamp (301s ago)
    const oldTs = currentTs - 301;
    const nonce2 = crypto.randomBytes(12).toString('hex');
    assert.throws(() => checkReplayAndSkew(oldTs, nonce2), /Timestamp expired/);
    console.log('  -> PASS: Timestamp skew check and nonce deduplication verified');
  }

  console.log('\n======================================================');
  console.log('  All SideVault cross-platform interop tests PASSED!  ');
  console.log('======================================================');
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
