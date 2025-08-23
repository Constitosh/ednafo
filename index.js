const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bitcoinMessage = require('bitcoinjs-message');
const bitcoin = require('bitcoinjs-lib');

const app = express();

// If frontend on same origin via Nginx proxy, CORS not required.
// Otherwise, configure:
// app.use(cors({ origin: 'https://your-frontend-domain.tld', credentials: true }));
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));

// Where we store results
const DATA_DIR = path.join(__dirname, 'data');
const FILE_PATH = path.join(DATA_DIR, 'submissions.jsonl');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(FILE_PATH)) fs.writeFileSync(FILE_PATH, '', 'utf8');

// util: extract client IP
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return req.ip;
}

// Try to verify a signed message if we have both address & signature
function verifyBtcSignature(address, message, signature) {
  try {
    // signature may be base64 (common) or hex; try base64 first, then hex
    let ok = false;
    try {
      ok = bitcoinMessage.verify(message, address, signature);
    } catch (_) {
      // try hex -> buffer -> base64
      const isHex = /^[0-9a-fA-F]+$/.test(signature);
      if (isHex) {
        const buf = Buffer.from(signature, 'hex');
        ok = bitcoinMessage.verify(message, address, buf.toString('base64'));
      }
    }
    return !!ok;
  } catch (e) {
    return false;
  }
}

app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.post('/api/submit', async (req, res) => {
  try {
    const { answers, btc, userAgent } = req.body || {};
    if (!Array.isArray(answers)) {
      return res.status(400).send('answers must be an array');
    }

    const ip = getClientIp(req);
    let signatureValid = null;

    if (btc?.address && btc?.signature && btc?.message) {
      signatureValid = verifyBtcSignature(btc.address, btc.message, btc.signature);
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
        provider: btc?.provider || null,
        verified: signatureValid
      }
    };

    fs.appendFileSync(FILE_PATH, JSON.stringify(entry) + '\n', 'utf8');
    res.json({ ok: true, verified: signatureValid });
  } catch (err) {
    console.error(err);
    res.status(500).send('server error');
  }
});

// Start server
const PORT = process.env.PORT || 3002;
app.listen(PORT, '0.0.0.0', () => {
  console.log('ednafo api listening on', PORT);
});
