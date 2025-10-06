import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import Busboy from 'busboy';
import crypto from 'crypto';
import fs from 'fs';
import { Readable, PassThrough } from 'stream';
import winston from 'winston';
import dotenv from 'dotenv';
import { create as createIpfs } from 'ipfs-http-client';
import AWS from 'aws-sdk';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Logger
if (!fs.existsSync('logs')) fs.mkdirSync('logs');
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// IPFS client (local)
const ipfs = createIpfs({
  host: process.env.IPFS_HOST || '127.0.0.1',
  port: parseInt(process.env.IPFS_PORT || '5001'),
  protocol: process.env.IPFS_PROTOCOL || 'http'
});

// Security middlewares
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: ['https://yourdomain.com', 'http://localhost:5173'] // 개발/운영 도메인 지정
}));

// Simple bearer token auth for API
app.use((req, res, next) => {
  const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (!token || token !== process.env.API_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// Rate limit
app.use('/api/', rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  standardHeaders: true,
  legacyHeaders: false
}));

app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), ts: new Date().toISOString() });
});

// ---- Key Management ----
const KEY_MODE = (process.env.KEY_MODE || 'LOCAL').toUpperCase();
let kms;
if (KEY_MODE === 'KMS') {
  AWS.config.update({ region: process.env.AWS_REGION || 'ap-northeast-2' });
  kms = new AWS.KMS();
}

function generateDataKeyLocal() {
  const key = crypto.randomBytes(32);
  const mk = Buffer.from(process.env.MASTER_KEY_HEX || '', 'hex');
  if (mk.length !== 32) throw new Error('MASTER_KEY_HEX invalid');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', mk, iv);
  const wrappedKey = Buffer.concat([cipher.update(key), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    plaintextKey: key,
    wrappedKey: wrappedKey.toString('hex'),
    wrappedKeyIv: iv.toString('hex'),
    wrappedKeyTag: tag.toString('hex')
  };
}

async function generateDataKeyKms() {
  const params = {
    KeyId: process.env.KMS_KEY_ID,
    KeySpec: 'AES_256'
  };
  const { Plaintext, CiphertextBlob } = await kms.generateDataKey(params).promise();
  return {
    plaintextKey: Buffer.from(Plaintext),
    kmsCiphertextBlob: CiphertextBlob.toString('base64')
  };
}

// ---- Upload & Encrypt (Streaming) ----
app.post('/api/upload-encrypt', async (req, res) => {
  try {
    const busboy = Busboy({ headers: req.headers, limits: { fileSize: parseInt(process.env.MAX_FILE_BYTES || '0') || undefined } });
    let responded = false;

    busboy.on('file', async (fieldname, file, filename, encoding, mimetype) => {
      try {
        // 1) Data key
        let dataKey, metaKey;
        if (KEY_MODE === 'KMS') {
          const out = await generateDataKeyKms();
          dataKey = out.plaintextKey;
          metaKey = { kmsCiphertextBlob: out.kmsCiphertextBlob };
        } else {
          const out = generateDataKeyLocal();
          dataKey = out.plaintextKey;
          metaKey = { wrappedKey: out.wrappedKey, wrappedKeyIv: out.wrappedKeyIv, wrappedKeyTag: out.wrappedKeyTag };
        }

        // 2) AES-256-GCM cipher stream
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);

        // 3) Pipe: file -> cipher -> ipfs.add
        const pass = new PassThrough();
        file.pipe(cipher).pipe(pass);

        const addRes = await ipfs.add({ content: pass, path: filename }, { pin: true });
        const cid = addRes.cid.toString();
        const authTag = cipher.getAuthTag();

        // 4) Hash(원본) 계산을 원하면 별도 tee 필요(성능 비용). 여기선 생략 또는 별도 구현.
        const metadata = {
          cid,
          originalName: filename,
          mimeType: mimetype,
          iv: iv.toString('hex'),
          authTag: authTag.toString('hex'),
          uploadedAt: new Date().toISOString(),
          keyMode: KEY_MODE,
          ...metaKey
        };

        responded = true;
        return res.json({ success: true, cid, metadata });
      } catch (e) {
        if (!responded) {
          responded = true;
          return res.status(500).json({ success: false, error: 'Upload failed', details: process.env.NODE_ENV !== 'production' ? e.message : undefined });
        }
      }
    });

    busboy.on('error', (err) => {
      if (!responded) res.status(500).json({ success: false, error: 'Busboy error' });
    });

    busboy.on('finish', () => {
      if (!responded) res.status(400).json({ success: false, error: 'No file' });
    });

    req.pipe(busboy);
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Unexpected error' });
  }
});

// ---- Download & Decrypt ----
app.get('/api/download/:cid', async (req, res) => {
  try {
    const cid = req.params.cid;
    const { iv, authTag, originalName, mimeType, wrappedKey, wrappedKeyIv, wrappedKeyTag, kmsCiphertextBlob } = req.query;
    if (!cid || !iv || !authTag) return res.status(400).json({ error: 'Missing parameters' });

    // unwrap key
    let dataKey;
    if (KEY_MODE === 'KMS' && kmsCiphertextBlob) {
      const out = await kms.decrypt({ CiphertextBlob: Buffer.from(kmsCiphertextBlob, 'base64') }).promise();
      dataKey = Buffer.from(out.Plaintext);
    } else if (wrappedKey && wrappedKeyIv && wrappedKeyTag) {
      const mk = Buffer.from(process.env.MASTER_KEY_HEX || '', 'hex');
      if (mk.length !== 32) throw new Error('MASTER_KEY_HEX invalid');
      const decipherKey = crypto.createDecipheriv('aes-256-gcm', mk, Buffer.from(wrappedKeyIv, 'hex'));
      decipherKey.setAuthTag(Buffer.from(wrappedKeyTag, 'hex'));
      dataKey = Buffer.concat([decipherKey.update(Buffer.from(wrappedKey, 'hex')), decipherKey.final()]);
    } else {
      return res.status(400).json({ error: 'Missing key wrapping parameters' });
    }

    // fetch encrypted content
    const stream = ipfs.cat(cid);
    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    res.setHeader('Content-Type', mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${originalName || 'download'}"`);
    // stream decrypt -> res
    Readable.from(stream).pipe(decipher).pipe(res);
  } catch (error) {
    res.status(500).json({ error: 'Download failed', details: process.env.NODE_ENV !== 'production' ? error.message : undefined });
  }
});

// IPFS status
app.get('/api/ipfs-status', async (req, res) => {
  try {
    const version = await ipfs.version();
    const id = await ipfs.id();
    res.json({ ok: true, version: version.version, id: id.id, addrs: id.addresses });
  } catch {
    res.status(500).json({ ok: false });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server listening on ${PORT} (${process.env.NODE_ENV})`);
});