const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bitcoinMessage = require('bitcoinjs-message');

const app = express();

/* --- Core server hardening & config --- */
app.set('trust proxy', true); // respect X-Forwarded-For / X-Real-IP from Nginx

// CORS: frontend is hosted on Webflow at this origin (domain only, no path)
const corsOptions = {
  origin: 'https://old-money.webflow.io',
  credentials: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // handle preflight for all routes

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

function verifyBtcSignature(address, message, signature) {
  try {
    // First try as-is (commonly base64)
    try {
      return !!bitcoinMessage.verify(message, address, signature);
    } catch {
      // If hex, convert to base64 and try again
      const isHex = /^[0-9a-fA-F]+$/.test(signature);
      if (isHex) {
        const buf = Buffer.from(signature, 'hex');
        return !!bitcoinMessage.verify(message, address, buf.toString('base64'));
      }
      return false;
    }
  } catch {
    return false;
  }
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
    console.error('submit error:', err);
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

/* --- Start server --- */
const PORT = process.env.PORT || 3002;
app.listen(PORT, '0.0.0.0', () => {
  console.log('ednafo api listening on', PORT);
});
