// server.js
// Ednafo API — saves submissions and verifies BTC signatures (ECDSA + BIP-322)
// Also serves self-hosted static files (e.g., sats-connect UMD) at /static/*

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bitcoinMessage = require('bitcoinjs-message');
const { Verifier } = require('bip322-js');

const app = express();

/* --- Core server hardening & config --- */
app.set('trust proxy', true); // respect X-Forwarded-For / X-Real-IP from Nginx

// CORS: frontend is hosted on Webflow at this origin (domain only, no path)
const corsOptions = {
  origin: 'https://oldmoney.io', // <-- add more origins here if needed
  credentials: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
};
app.use(cors(corsOptions));
app.options('/health', cors(corsOptions));
app.options('/api/submit', cors(corsOptions));

/* --- Static hosting for self-hosted libs (e.g., sats-connect UMD) --- */
const STATIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(STATIC_DIR)) fs.mkdirSync(STATIC_DIR, { recursive: true });

// Serve /static/* from ./public (cache JS for a week)
app.use('/static', express.static(STATIC_DIR, {
  maxAge: '7d',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
      // You can tighten CSP at the reverse proxy; here we only serve the file.
    }
  }
}));

// JSON body limit can be small; signatures are short
app.use(bodyParser.json({ limit: '1mb' }));

/* --- Data file setup --- */
const DATA_DIR = path.join(__dirname, 'data');
const FILE_PATH = path.join(DATA_DIR, 'submissions.jsonl');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(FILE_PATH)) fs.writeFileSync(FILE_PATH, '', 'utf8');

/* --- Helpers --- */
function getClientIp(req) {
  // With trust proxy = true, req.ip is the real client IP (left-most in X-Forwarded-For)
  return req.ip;
}

function isTaproot(addr) {
  // Mainnet Taproot bech32m addresses start with bc1p...
  return typeof addr === 'string' && /^bc1p[0-9a-z]+$/.test(addr);
}

function verifyWithBitcoinJsMessage(address, message, signature) {
  // Try base64 first (typical), then hex->base64 fallback
  try {
    return !!bitcoinMessage.verify(message, address, signature);
  } catch {
    try {
      const isHex = /^[0-9a-fA-F]+$/.test(signature);
      if (!isHex) return false;
      const buf = Buffer.from(signature, 'hex');
      return !!bitcoinMessage.verify(message, address, buf.toString('base64'));
    } catch {
      return false;
    }
  }
}

function verifyWithBip322(address, message, signature) {
  try {
    // bip322-js verifies the "simple" signature used by Xverse for Taproot
    return Verifier.verifySignature(address, message, signature);
  } catch {
    return false;
  }
}

/**
 * Detect protocol (or honor a provided one) and verify accordingly.
 * Returns { ok: boolean, protocol: 'ecdsa'|'bip322'|null }
 */
function verifyBtcSignature(address, message, signature, declaredProtocol) {
  const proto = declaredProtocol || (isTaproot(address) ? 'bip322' : 'ecdsa');

  if (proto === 'bip322') {
    return { ok: verifyWithBip322(address, message, signature), protocol: 'bip322' };
  }

  // default ECDSA path
  const ok = verifyWithBitcoinJsMessage(address, message, signature);

  // If ECDSA fails but the address looks Taproot, try BIP-322 as a safety net
  if (!ok && isTaproot(address)) {
    return { ok: verifyWithBip322(address, message, signature), protocol: 'bip322' };
  }
  return { ok, protocol: 'ecdsa' };
}

/* --- Routes --- */
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.post('/api/submit', (req, res) => {
  try {
    const { answers, btc, userAgent } = req.body || {};
    if (!Array.isArray(answers)) {
      return res.status(400).json({ ok: false, error: 'answers must be an array' });
    }

    const ip = getClientIp(req);
    let signatureValid = null;
    let detectedProtocol = null;

    if (btc?.address && btc?.signature && btc?.message) {
      const result = verifyBtcSignature(
        btc.address,
        btc.message,
        btc.signature,
        // optional front-end hint: 'ecdsa' | 'bip322'
        btc?.protocol
      );
      signatureValid = result.ok;
      detectedProtocol = result.protocol;
    }

    const entry = {
      ts: new Date().toISOString(),
      ip,
      userAgent: userAgent || null,
      answers,
      btc: {
        address: btc?.address || null,
        signature: btc?.signature || null,
        message: btc?.message || null,
        provider: btc?.provider || null,    // 'xverse' | 'unisat' | 'leather' | ...
        protocol: btc?.protocol || detectedProtocol || null, // 'ecdsa' | 'bip322'
        verified: signatureValid
      }
    };

    fs.appendFileSync(FILE_PATH, JSON.stringify(entry) + '\n', 'utf8');
    res.json({ ok: true, verified: signatureValid, protocol: detectedProtocol });
  } catch (err) {
    console.error('submit error:', err);
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

/* --- Start server --- */
const PORT = process.env.PORT || 3002;
app.listen(PORT, '0.0.0.0', () => {
  console.log('ednafo api listening on', PORT);
});
