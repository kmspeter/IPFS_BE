const express = require('express');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto-js');
const fs = require('fs').promises;
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ---- IPFS 클라이언트 (동적 import + lazy init) ----
let _ipfsClient = null;
const getIpfs = async () => {
  if (_ipfsClient) return _ipfsClient;
  const { create } = await import('ipfs-http-client'); // ESM 동적 import
  const apiUrl = process.env.IPFS_API_URL || 'http://127.0.0.1:5001/api/v0';
  _ipfsClient = create({ url: apiUrl });
  return _ipfsClient;
};

// (Node < 18 환경 대비) fetch 폴리필
if (typeof fetch === 'undefined') {
  global.fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
}

// 미들웨어 설정
app.use(helmet({
  // 교차 출처 다운로드(파일 응답) 시 정책 완화가 필요한 경우에만 유지
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression());
app.use(morgan('combined'));

// 여러 오리진 허용 + 프리플라이트 대응
const allowedOrigins = (process.env.ALLOWED_ORIGINS
  || 'https://ai-modelhub-platform.vercel.app,http://localhost:5173')
  .split(',')
  .map(s => s.trim());

app.use(cors({
  origin(origin, cb) {
    // 서버-서버/모바일앱 등 Origin 없는 요청은 허용
    if (!origin) return cb(null, true);
    return allowedOrigins.includes(origin)
      ? cb(null, true)
      : cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 프리플라이트(OPTIONS) 응답
app.options(/.*/, cors());

app.use(express.json({ limit: '10mb' }));

// Multer 설정 (임시 파일 저장)
const storage = multer.diskStorage({
  // multer의 destination 콜백은 async를 공식지원하진 않지만, 내부에서 await 후 cb 호출하도록 유지
  destination: async (req, file, cb) => {
    try {
      const uploadDir = 'uploads/';
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (e) {
      cb(e);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB 제한
  }
});

// 모델 등록 전용 업로드 (대용량 지원)
const registerUpload = multer({
  storage: storage,
  limits: {
    fileSize: Number(process.env.REGISTER_FILE_LIMIT || 1024 * 1024 * 1024 * 4) // 기본 4GB
  }
});

const BACKEND_REGISTER_ENDPOINT = 'https://kau-capstone.duckdns.org/model/register';

// 암호화 키 생성 함수
const generateEncryptionKey = () => {
  return crypto.lib.WordArray.random(256 / 8).toString();
};

// 파일 암호화 함수
const encryptFile = async (filePath, encryptionKey) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileContent = fileBuffer.toString('base64');

    // AES 암호화
    const encrypted = crypto.AES.encrypt(fileContent, encryptionKey).toString();

    return Buffer.from(encrypted);
  } catch (error) {
    throw new Error('파일 암호화 실패: ' + error.message);
  }
};

// 파일 복호화 함수
const decryptFile = (encryptedData, encryptionKey) => {
  try {
    const decrypted = crypto.AES.decrypt(encryptedData.toString(), encryptionKey);
    const decryptedBase64 = decrypted.toString(crypto.enc.Utf8);

    return Buffer.from(decryptedBase64, 'base64');
  } catch (error) {
    throw new Error('파일 복호화 실패: ' + error.message);
  }
};

// 헬스체크 엔드포인트
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// IPFS 연결 상태 확인
app.get('/ipfs/status', async (req, res) => {
  try {
    const ipfs = await getIpfs();
    const id = await ipfs.id();
    res.json({
      status: 'connected',
      peerId: id.id,
      addresses: id.addresses
    });
  } catch (error) {
    res.status(500).json({
      status: 'disconnected',
      error: error.message
    });
  }
});

// 파일 업로드 및 암호화 후 IPFS 저장
app.post('/upload', upload.single('file'), async (req, res) => {
  let filePath = null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: '파일이 제공되지 않았습니다.' });
    }

    filePath = req.file.path;

    // 암호화 키 생성
    const encryptionKey = generateEncryptionKey();

    // 파일 암호화
    console.log('파일 암호화 중...');
    const encryptedBuffer = await encryptFile(filePath, encryptionKey);

    // IPFS에 암호화된 파일 업로드
    console.log('IPFS에 업로드 중...');
    const ipfs = await getIpfs();
    const addResult = await ipfs.add(encryptedBuffer, {
      progress: (prog) => console.log(`업로드 진행률: ${prog}`)
    });

    // 최신 ipfs-http-client는 cid 중심 반환
    const ipfsHash = (addResult.cid ?? addResult.path).toString();

    // 메타데이터 생성
    const metadata = {
      originalName: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype,
      uploadDate: new Date().toISOString(),
      ipfsHash: ipfsHash,
      encrypted: true
    };

    // 메타데이터도 IPFS에 저장
    const metadataResult = await ipfs.add(JSON.stringify(metadata));
    const metadataHash = (metadataResult.cid ?? metadataResult.path).toString();

    // 임시 파일 삭제
    await fs.unlink(filePath);

    // 응답 (프론트로 encryptionKey 절대 전달하지 않음)
    res.json({
      success: true,
      data: {
        ipfsHash: ipfsHash,
        metadataHash: metadataHash,
        gateway: `http://${req.hostname}:8080/ipfs/${ipfsHash}`,
        metadata: metadata
      }
    });

  } catch (error) {
    console.error('업로드 에러:', error);

    // 에러 발생 시 임시 파일 삭제
    if (filePath) {
      await fs.unlink(filePath).catch(console.error);
    }

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 모델 파일 + 메타데이터 등록 (IPFS 업로드 후 백엔드 릴레이)
app.post('/ipfs/register', registerUpload.fields([
  { name: 'model', maxCount: 1 },
  { name: 'metadata', maxCount: 1 }
]), async (req, res) => {
  const controller = new AbortController();
  let modelFilePath = null;
  let metadataFilePath = null;
  let responded = false;

  const cleanupTempFiles = async () => {
    const tasks = [];
    if (modelFilePath) tasks.push(fs.unlink(modelFilePath).catch(() => {}));
    if (metadataFilePath) tasks.push(fs.unlink(metadataFilePath).catch(() => {}));
    await Promise.all(tasks);
  };

  const abortHandler = async () => {
    if (responded) return;
    responded = true;
    controller.abort();
    await cleanupTempFiles();
  };

  req.on('aborted', () => {
    console.warn('요청 연결이 중단되어 업로드를 취소합니다.');
    abortHandler().catch(console.error);
  });

  try {
    const modelFiles = req.files?.model || [];
    if (!modelFiles.length) {
      responded = true;
      await cleanupTempFiles();
      return res.status(400).json({ success: false, error: '모델 파일이 필요합니다.' });
    }

    const modelFile = modelFiles[0];
    modelFilePath = modelFile.path;

    const metadataFiles = req.files?.metadata || [];
    if (metadataFiles.length) {
      metadataFilePath = metadataFiles[0].path;
    }

    let metadataJson = null;
    try {
      if (metadataFilePath) {
        const raw = await fs.readFile(metadataFilePath, 'utf8');
        metadataJson = JSON.parse(raw);
      } else if (typeof req.body?.metadata === 'string') {
        metadataJson = JSON.parse(req.body.metadata);
      }
    } catch (parseErr) {
      responded = true;
      await cleanupTempFiles();
      return res.status(400).json({ success: false, error: '메타데이터 파싱 실패: ' + parseErr.message });
    }

    if (!metadataJson) {
      responded = true;
      await cleanupTempFiles();
      return res.status(400).json({ success: false, error: '메타데이터가 필요합니다.' });
    }

    const encryptionKey = generateEncryptionKey();
    console.log('[register] 파일 암호화 시작');
    const encryptedBuffer = await encryptFile(modelFilePath, encryptionKey);

    console.log('[register] IPFS 업로드 시작');
    const ipfs = await getIpfs();
    let addResult;
    try {
      addResult = await ipfs.add(encryptedBuffer, {
        signal: controller.signal,
        progress: (prog) => console.log(`[register] 업로드 진행률: ${prog}`)
      });
    } catch (err) {
      if (controller.signal.aborted) {
        responded = true;
        await cleanupTempFiles();
        return; // 요청이 이미 중단됨
      }
      throw err;
    }

    const ipfsHash = (addResult.cid ?? addResult.path).toString();

    const registrationMetadata = {
      originalName: modelFile.originalname,
      size: modelFile.size,
      mimeType: modelFile.mimetype,
      uploadDate: new Date().toISOString(),
      ipfsHash,
      encrypted: true,
      payload: metadataJson || null
    };

    const metadataResult = await ipfs.add(JSON.stringify(registrationMetadata), { signal: controller.signal });
    const metadataHash = (metadataResult.cid ?? metadataResult.path).toString();

    const gateway = `http://${req.hostname}:8080/ipfs/${ipfsHash}`;

    // 고정된 백엔드로 릴레이 (항상 시도) — 백엔드에는 encryptionKey 포함
    console.log('[register] 백엔드로 릴레이 요청 전송');
    const relayBody = {
      ...(metadataJson || {}),
      ipfs: {
        hash: ipfsHash,
        metadataHash,
        encryptionKey, // 백엔드에만 전달
        gateway
      }
    };

    const backendRes = await fetch(BACKEND_REGISTER_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(relayBody)
    });

    const backendText = await backendRes.text();

    if (!backendRes.ok) {
      // 백엔드가 200-299가 아니면 실패 처리
      throw new Error(`백엔드 전송 실패 (${backendRes.status}): ${backendText}`);
    }

    responded = true;
    await cleanupTempFiles();

    // 성공 시 프론트로 encryptionKey를 절대 전달하지 않고 등록 완료만 알림
    return res.json({
      success: true,
      data: {
        ipfsHash,
        metadataHash,
        gateway,
        registered: true
      }
    });
  } catch (error) {
    console.error('모델 등록 실패:', error);
    if (!responded) {
      responded = true;
      await cleanupTempFiles();
      return res.status(500).json({ success: false, error: error.message });
    }
  }
});

// IPFS에서 파일 가져오기 및 복호화
app.post('/retrieve', async (req, res) => {
  try {
    const { ipfsHash, encryptionKey, metadataHash } = req.body;

    if (!ipfsHash || !encryptionKey) {
      return res.status(400).json({
        error: 'IPFS 해시와 암호화 키가 필요합니다.'
      });
    }

    const ipfs = await getIpfs();

    // IPFS에서 암호화된 파일 가져오기
    console.log('IPFS에서 파일 가져오는 중...');
    const chunks = [];
    for await (const chunk of ipfs.cat(ipfsHash)) {
      chunks.push(chunk);
    }
    const encryptedData = Buffer.concat(chunks);

    // 파일 복호화
    console.log('파일 복호화 중...');
    const decryptedBuffer = decryptFile(encryptedData, encryptionKey);

    // 메타데이터 가져오기 (옵션)
    let metadata = null;
    if (metadataHash) {
      const metaChunks = [];
      for await (const chunk of ipfs.cat(metadataHash)) {
        metaChunks.push(chunk);
      }
      metadata = JSON.parse(Buffer.concat(metaChunks).toString());
    }

    // 파일 전송
    res.set({
      'Content-Type': metadata?.mimeType || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${metadata?.originalName || 'file'}"`
    });
    res.send(decryptedBuffer);

  } catch (error) {
    console.error('파일 검색 에러:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 파일 목록 조회 (메타데이터)
app.get('/files/:metadataHash', async (req, res) => {
  try {
    const { metadataHash } = req.params;
    const ipfs = await getIpfs();

    const chunks = [];
    for await (const chunk of ipfs.cat(metadataHash)) {
      chunks.push(chunk);
    }

    const metadata = JSON.parse(Buffer.concat(chunks).toString());
    res.json(metadata);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 서버 시작
app.listen(PORT, '0.0.0.0', () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
  console.log(`IPFS Gateway: http://localhost:8080`);
});
