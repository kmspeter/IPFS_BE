const express = require('express');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto-js');
const fs = require('fs').promises;
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ---- S3 클라이언트 설정 ----
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'ap-northeast-2',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const S3_BUCKET = process.env.S3_BUCKET_NAME || 'ai-model-hub';
const S3_BASE_URL = process.env.S3_BASE_URL || `https://${S3_BUCKET}.s3.${process.env.AWS_REGION || 'ap-northeast-2'}.amazonaws.com`;

// S3 업로드 헬퍼 함수
const uploadToS3 = async (filePath, fileName, mimeType) => {
  try {
    const fileContent = await fs.readFile(filePath);
    const key = `model-assets/${Date.now()}-${fileName}`;

    const command = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: fileContent,
      ContentType: mimeType,
      // ACL: 'public-read' // 퍼블릭 읽기 권한 (필요시)
    });

    await s3Client.send(command);

    // S3 URL 반환
    return `${S3_BASE_URL}/${key}`;
  } catch (error) {
    console.error('S3 업로드 실패:', error);
    throw new Error('S3 업로드 실패: ' + error.message);
  }
};

// ---- IPFS 클라이언트 (동적 import + lazy init) ----
let _ipfsClient = null;
const getIpfs = async () => {
  if (_ipfsClient) return _ipfsClient;
  const { create } = await import('ipfs-http-client');
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
    if (!origin) return cb(null, true);
    return allowedOrigins.includes(origin)
      ? cb(null, true)
      : cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options(/.*/, cors());
app.use(express.json({ limit: '10mb' }));

// Multer 설정 (임시 파일 저장)
const storage = multer.diskStorage({
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

const BACKEND_REGISTER_ENDPOINT = process.env.BACKEND_REGISTER_ENDPOINT || 'https://kau-capstone.duckdns.org/model/register';

// 암호화 키 생성 함수
const generateEncryptionKey = () => {
  return crypto.lib.WordArray.random(256 / 8).toString();
};

// 파일 암호화 함수
const encryptFile = async (filePath, encryptionKey) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const fileContent = fileBuffer.toString('base64');
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

// S3 연결 상태 확인
app.get('/s3/status', async (req, res) => {
  try {
    // 간단한 테스트 업로드
    const testKey = `health-check/${Date.now()}.txt`;
    const command = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: testKey,
      Body: 'health check',
      ContentType: 'text/plain'
    });
    
    await s3Client.send(command);
    
    res.json({
      status: 'connected',
      bucket: S3_BUCKET,
      region: process.env.AWS_REGION || 'ap-northeast-2'
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
    const encryptionKey = generateEncryptionKey();

    console.log('파일 암호화 중...');
    const encryptedBuffer = await encryptFile(filePath, encryptionKey);

    console.log('IPFS에 업로드 중...');
    const ipfs = await getIpfs();
    const addResult = await ipfs.add(encryptedBuffer, {
      progress: (prog) => console.log(`업로드 진행률: ${prog}`)
    });

    const ipfsHash = (addResult.cid ?? addResult.path).toString();

    const metadata = {
      originalName: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype,
      uploadDate: new Date().toISOString(),
      ipfsHash: ipfsHash,
      encrypted: true
    };

    const metadataResult = await ipfs.add(JSON.stringify(metadata));
    const metadataHash = (metadataResult.cid ?? metadataResult.path).toString();

    await fs.unlink(filePath);

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
    if (filePath) {
      await fs.unlink(filePath).catch(console.error);
    }
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 모델 파일 + 메타데이터 등록 (IPFS 업로드 + S3 업로드 + 백엔드 릴레이)
app.post('/ipfs/register', registerUpload.fields([
  { name: 'model', maxCount: 1 },
  { name: 'metadata', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 },
  { name: 'sample-prompt', maxCount: 1 },
  { name: 'sample-output', maxCount: 1 },
  { name: 'sample-outputImage', maxCount: 1 },
  { name: 'sample-inputImage', maxCount: 1 },
  { name: 'sample-inputAudio', maxCount: 1 }
]), async (req, res) => {
  const controller = new AbortController();
  let responded = false;
  const tempFiles = [];

  const cleanupTempFiles = async () => {
    const tasks = tempFiles.map(fp => fs.unlink(fp).catch(() => {}));
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
    // 1. 모델 파일 확인
    const modelFiles = req.files?.model || [];
    if (!modelFiles.length) {
      responded = true;
      await cleanupTempFiles();
      return res.status(400).json({ success: false, error: '모델 파일이 필요합니다.' });
    }

    const modelFile = modelFiles[0];
    tempFiles.push(modelFile.path);

    // 2. 메타데이터 파싱
    const metadataFiles = req.files?.metadata || [];
    if (metadataFiles.length) {
      tempFiles.push(metadataFiles[0].path);
    }

    let metadataJson = null;
    try {
      if (metadataFiles.length) {
        const raw = await fs.readFile(metadataFiles[0].path, 'utf8');
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

    // 3. 썸네일 파일 S3 업로드
    let thumbnailUrl = null;
    const thumbnailFiles = req.files?.thumbnail || [];
    if (thumbnailFiles.length) {
      const thumbnailFile = thumbnailFiles[0];
      tempFiles.push(thumbnailFile.path);
      
      console.log('[register] 썸네일 S3 업로드 시작');
      thumbnailUrl = await uploadToS3(
        thumbnailFile.path,
        thumbnailFile.originalname,
        thumbnailFile.mimetype
      );
      console.log('[register] 썸네일 S3 URL:', thumbnailUrl);
    }

    // 4. 샘플 파일들 S3 업로드
    const sampleFileFields = [
      'sample-outputImage',
      'sample-inputImage', 
      'sample-inputAudio'
    ];

    const sampleUrls = {};
    for (const fieldName of sampleFileFields) {
      const files = req.files?.[fieldName] || [];
      if (files.length) {
        const file = files[0];
        tempFiles.push(file.path);
        
        console.log(`[register] ${fieldName} S3 업로드 시작`);
        const s3Url = await uploadToS3(
          file.path,
          file.originalname,
          file.mimetype
        );
        
        // fieldName에서 'sample-' 제거하여 키 생성
        const key = fieldName.replace('sample-', '');
        sampleUrls[key] = s3Url;
        console.log(`[register] ${fieldName} S3 URL:`, s3Url);
      }
    }

    // 5. 모델 파일 암호화
    const encryptionKey = generateEncryptionKey();
    console.log('[register] 모델 파일 암호화 시작');
    const encryptedBuffer = await encryptFile(modelFile.path, encryptionKey);

    // 6. IPFS 업로드
    console.log('[register] IPFS 업로드 시작');
    const ipfs = await getIpfs();
    let addResult;
    try {
      addResult = await ipfs.add(encryptedBuffer, {
        signal: controller.signal,
        progress: (prog) => console.log(`[register] IPFS 업로드 진행률: ${prog}`)
      });
    } catch (err) {
      if (controller.signal.aborted) {
        responded = true;
        await cleanupTempFiles();
        return;
      }
      throw err;
    }

    const ipfsHash = (addResult.cid ?? addResult.path).toString();
    console.log('[register] IPFS 업로드 완료:', ipfsHash);

    // 7. IPFS 메타데이터 저장
    const registrationMetadata = {
      originalName: modelFile.originalname,
      size: modelFile.size,
      mimeType: modelFile.mimetype,
      uploadDate: new Date().toISOString(),
      ipfsHash,
      encrypted: true,
      payload: metadataJson || null
    };

    const metadataResult = await ipfs.add(JSON.stringify(registrationMetadata), { 
      signal: controller.signal 
    });
    const metadataHash = (metadataResult.cid ?? metadataResult.path).toString();

    const gateway = `http://${req.hostname}:8080/ipfs/${ipfsHash}`;

    // 8. 백엔드로 릴레이할 데이터 구성
    console.log('[register] 백엔드로 릴레이 요청 준비');

    // 메타데이터의 sample 객체 수정: S3 URL로 교체
    const modifiedMetadata = { ...metadataJson };
    
    if (modifiedMetadata.sample) {
      // 썸네일 URL 추가
      if (thumbnailUrl) {
        modifiedMetadata.thumbnail = thumbnailUrl;
      }

      // 샘플 파일 URL로 교체
      Object.keys(sampleUrls).forEach(key => {
        if (modifiedMetadata.sample[key]) {
          modifiedMetadata.sample[key] = sampleUrls[key];
        }
      });
    }

    const relayBody = {
      ...modifiedMetadata,
      cidRoot: ipfsHash,
      encryptionKey
    };

    console.log('[register] 백엔드로 전달되는 데이터:', JSON.stringify(relayBody, null, 2));

    // 9. 백엔드로 전송
    const backendRes = await fetch(BACKEND_REGISTER_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(relayBody),
      signal: controller.signal
    });

    console.log(`[register] 백엔드 응답 status=${backendRes.status} ok=${backendRes.ok}`);

    const backendText = await backendRes.text();

    if (!backendRes.ok) {
      throw new Error(`백엔드 전송 실패 (${backendRes.status}): ${backendText}`);
    }

    // 10. 임시 파일 정리
    responded = true;
    await cleanupTempFiles();

    // 11. 성공 응답
    return res.json({
      success: true,
      message: '모델이 성공적으로 등록되었습니다.',
      data: {
        ipfsHash,
        metadataHash,
        gateway,
        thumbnailUrl,
        sampleUrls,
        registered: true
      }
    });

  } catch (error) {
    console.error('[register] 모델 등록 실패:', error);
    if (!responded) {
      responded = true;
      await cleanupTempFiles();
      return res.status(500).json({ 
        success: false, 
        error: error.message 
      });
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

    console.log('IPFS에서 파일 가져오는 중...');
    const chunks = [];
    for await (const chunk of ipfs.cat(ipfsHash)) {
      chunks.push(chunk);
    }
    const encryptedData = Buffer.concat(chunks);

    console.log('파일 복호화 중...');
    const decryptedBuffer = decryptFile(encryptedData, encryptionKey);

    let metadata = null;
    if (metadataHash) {
      const metaChunks = [];
      for await (const chunk of ipfs.cat(metadataHash)) {
        metaChunks.push(chunk);
      }
      metadata = JSON.parse(Buffer.concat(metaChunks).toString());
    }

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
  console.log(`S3 Bucket: ${S3_BUCKET}`);
  console.log(`Backend Endpoint: ${BACKEND_REGISTER_ENDPOINT}`);
});