require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const multer = require('multer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// ========== 环境变量检查 ==========
if (!process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET 未配置');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL 未配置');
  process.exit(1);
}

const app = express();
const server = http.createServer(app);

// ========== Render 反向代理信任 ==========
app.set('trust proxy', 1);

// ========== CORS 安全配置 ==========
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGIN
  ? process.env.ALLOWED_ORIGIN.split(',').map(o => o.trim())
  : true;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({
  origin: ALLOWED_ORIGINS,
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '登录尝试过多，请15分钟后再试' }
});
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: '搜索太频繁，请稍后再试' }
});
const friendRequestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: '请求太频繁，请稍后再试' }
});

// ========== 目录与 JSON 双保存配置 ==========
const DATA_FILE = path.join(__dirname, 'data', 'data.json');

let users = new Map();
const usernameIndex = new Map();
const inviteIndex = new Map();
const fileOwners = new Map();
let messages = [];
let friendRequests = [];
let groups = [];
let notifications = [];
let uidCounter = 1;
let msgIdCounter = 1;
let reqIdCounter = 1;
let groupIdCounter = 1;

function exportData() {
  return {
    users: Array.from(users.entries()).map(([id, user]) => ({
      ...user,
      friends: [...user.friends],
      groups: [...user.groups],
      clearedTimestamps: user.clearedTimestamps || {}
    })),
    messages,
    friendRequests,
    groups: groups.map(g => ({
      ...g,
      members: Array.from(g.members.entries())
    })),
    notifications,
    counters: { uidCounter, msgIdCounter, reqIdCounter, groupIdCounter }
  };
}

function saveData() {
  const temp = DATA_FILE + '.tmp';
  try {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(temp, JSON.stringify(exportData(), null, 2));
    fs.renameSync(temp, DATA_FILE);
  } catch (e) {
    console.error('保存 data.json 失败', e);
  }
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) return;
  try {
    const raw = fs.readFileSync(DATA_FILE);
    const data = JSON.parse(raw);
    users = new Map();
    usernameIndex.clear();
    inviteIndex.clear();
    data.users.forEach(u => {
      const user = { ...u, friends: new Set(u.friends), groups: new Set(u.groups) };
      user.avatar = user.avatar || '';
      user.chatBackground = user.chatBackground || '';
      user.nickname = sanitizeText(user.nickname || '');
      user.signature = sanitizeText(user.signature || '');
      user.clearedTimestamps = u.clearedTimestamps || {};
      users.set(user.id, user);
      usernameIndex.set(user.username, user);
      if (user.inviteCode) inviteIndex.set(user.inviteCode, user);
    });
    messages = data.messages || [];
    messages.forEach(m => { if (!m.type) m.type = 'text'; });
    friendRequests = data.friendRequests || [];
    groups = (data.groups || []).map(g => ({
      ...g,
      members: new Map(g.members || [])
    }));
    notifications = data.notifications || [];
    const counters = data.counters || {};
    uidCounter = counters.uidCounter || 1;
    msgIdCounter = counters.msgIdCounter || 1;
    reqIdCounter = counters.reqIdCounter || 1;
    groupIdCounter = counters.groupIdCounter || 1;
    console.log('已从 data.json 加载历史数据（双保存备份）');
  } catch (e) {
    console.error('加载 data.json 失败', e);
  }
}

loadData();
setInterval(saveData, 30000);

// ========== PostgreSQL 数据库连接 ==========
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ========== Session 持久化到 PostgreSQL ==========
const sessionMiddleware = session({
  store: new pgSession({
    pool: db,
    tableName: 'session',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});
app.use(sessionMiddleware);

// ========== 文件上传配置 ==========
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const ALLOWED_FILE_TYPES = {
  'jpg': { ext: '.jpg', mime: 'image/jpeg', maxSize: 5 * 1024 * 1024 },
  'jpeg': { ext: '.jpeg', mime: 'image/jpeg', maxSize: 5 * 1024 * 1024 },
  'png': { ext: '.png', mime: 'image/png', maxSize: 5 * 1024 * 1024 },
  'gif': { ext: '.gif', mime: 'image/gif', maxSize: 5 * 1024 * 1024 },
  'webp': { ext: '.webp', mime: 'image/webp', maxSize: 5 * 1024 * 1024 },
  'mp3': { ext: '.mp3', mime: 'audio/mpeg', maxSize: 10 * 1024 * 1024 },
  'wav': { ext: '.wav', mime: 'audio/wav', maxSize: 10 * 1024 * 1024 },
  'ogg': { ext: '.ogg', mime: 'audio/ogg', maxSize: 10 * 1024 * 1024 },
  'mp4': { ext: '.mp4', mime: 'video/mp4', maxSize: 15 * 1024 * 1024 },
  'webm': { ext: '.webm', mime: 'video/webm', maxSize: 15 * 1024 * 1024 },
  'pdf': { ext: '.pdf', mime: 'application/pdf', maxSize: 20 * 1024 * 1024 },
  'zip': { ext: '.zip', mime: 'application/zip', maxSize: 20 * 1024 * 1024 },
  'txt': { ext: '.txt', mime: 'text/plain', maxSize: 5 * 1024 * 1024 }
};

function getFileTypeInfo(filename) {
  const ext = path.extname(filename).toLowerCase().substring(1);
  return ALLOWED_FILE_TYPES[ext] || null;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const info = getFileTypeInfo(file.originalname);
    if (!info) return cb(new Error('不支持的文件类型'));
    const name = crypto.randomBytes(8).toString('hex') + info.ext;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const info = getFileTypeInfo(file.originalname);
    if (!info) return cb(new Error('不支持的文件类型'));
    cb(null, true);
  }
});

function validateMagicNumber(filePath, expectedType) {
  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.alloc(12);
  try {
    fs.readSync(fd, buffer, 0, 12, 0);
  } finally {
    fs.closeSync(fd);
  }
  const hex = buffer.toString('hex').toLowerCase();
  const signatures = {
    'jpg': 'ffd8',
    'jpeg': 'ffd8',
    'png': '89504e470d0a1a0a',
    'gif': '47494638',
    'webp': '52494646',
    'pdf': '255044462d',
    'zip': '504b0304',
    'mp3': '494433',
    'mp4': '000000',
    'webm': '1a45df',
    'wav': '524946',
    'ogg': '4f6767'
  };
  const expectedHex = signatures[expectedType];
  if (!expectedHex) return true;
  return hex.startsWith(expectedHex);
}

app.use(express.static(path.join(__dirname, 'public')));

// ========== 在线用户 Map ==========
const onlineUsers = new Map();

// ========== 数据库初始化 ==========
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      sid VARCHAR PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP NOT NULL
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      nickname VARCHAR(50) DEFAULT '',
      avatar VARCHAR(255) DEFAULT '',
      chat_background VARCHAR(255) DEFAULT '',
      gender VARCHAR(10) DEFAULT '',
      region VARCHAR(50) DEFAULT '',
      signature VARCHAR(200) DEFAULT '',
      invite_code VARCHAR(20) UNIQUE,
      invited_by VARCHAR(20),
      privacy_allow_search BOOLEAN DEFAULT true,
      cleared_timestamps JSONB DEFAULT '{}',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
      id SERIAL PRIMARY KEY,
      from_user INTEGER REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER REFERENCES users(id) ON DELETE CASCADE,
      message VARCHAR(200) DEFAULT '',
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS friends (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      friend_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, friend_id)
    );

    CREATE TABLE IF NOT EXISTS groups (
      id SERIAL PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS group_members (
      group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(20) DEFAULT 'member',
      joined_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (group_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_user INTEGER REFERENCES users(id) ON DELETE CASCADE,
      to_user INTEGER,
      group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
      type VARCHAR(20) DEFAULT 'text',
      content TEXT NOT NULL,
      file_name VARCHAR(255),
      duration REAL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      message TEXT,
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS uploaded_files (
      id SERIAL PRIMARY KEY,
      filename VARCHAR(255) NOT NULL,
      owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      upload_time TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS invite_codes (
      id SERIAL PRIMARY KEY,
      code VARCHAR(50) UNIQUE NOT NULL,
      creator INTEGER REFERENCES users(id) ON DELETE SET NULL,
      is_permanent BOOLEAN DEFAULT false,
      max_uses INTEGER DEFAULT 1,
      used_count INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    INSERT INTO invite_codes (code, creator, is_permanent, max_uses, used_count)
    VALUES ('20040705', NULL, true, 99999, 0)
    ON CONFLICT (code) DO NOTHING;
  `);

  try {
    const { rows } = await db.query('SELECT filename, owner_id FROM uploaded_files');
    rows.forEach(r => fileOwners.set(r.filename, r.owner_id));
    console.log(`已从数据库恢复 ${rows.length} 个文件所有者记录`);
  } catch (err) {
    console.error('恢复文件所有者记录失败', err);
  }
}

// ========== 工具函数 ==========
function sanitizeText(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/<[^>]*>/g, '').replace(/[<>"']/g, '').substring(0, 500);
}

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: '未登录' });
  }
  req.userId = req.session.userId;
  next();
}

// ========== Socket.IO 配置 ==========
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    credentials: true
  }
});

io.engine.use(sessionMiddleware);

io.use(async (socket, next) => {
  const session = socket.request.session;
  if (session && session.userId) {
    try {
      const res = await db.query('SELECT id FROM users WHERE id = $1', [session.userId]);
      if (res.rows.length > 0) {
        socket.userId = session.userId;
        socket.msgTimestamps = [];
        next();
      } else {
        next(new Error('用户不存在'));
      }
    } catch (err) {
      next(new Error('数据库错误'));
    }
  } else {
    next(new Error('认证失败'));
  }
});

const processedMsgIds = new Set();
setInterval(() => processedMsgIds.clear(), 5 * 60 * 1000);

io.on('connection', (socket) => {
  if (socket.userId) {
    onlineUsers.set(socket.userId, socket.id);
    socket.join(`user_${socket.userId}`);
    console.log(`用户 ${socket.userId} 已连接，当前在线用户数：${onlineUsers.size}`);
  }

  socket.on("login", async (userId) => {
    if (userId) {
      onlineUsers.set(userId, socket.id);
      console.log("在线用户表：", onlineUsers);
      try {
        const result = await db.query(
          "SELECT * FROM friend_requests WHERE to_user = $1 AND status = 'pending'",
          [userId]
        );
        socket.emit("pending_friend_requests", result.rows);
      } catch (err) {
        console.error("拉取未读好友申请失败", err);
      }
    }
  });

  socket.on("friend_request", ({ fromId, toId }) => {
    console.log("收到好友申请事件", { fromId, toId });
    const socketId = onlineUsers.get(toId);
    console.log("目标socket:", socketId);
    if (socketId) {
      io.to(socketId).emit("friend_request_received", {
        fromId,
        toId
      });
    }
  });

  socket.on("accept_friend", async ({ requestId, fromId, toId }) => {
    if (socket.userId !== toId) {
      return socket.emit("error", { message: "无权操作" });
    }
    try {
      const updateRes = await db.query(
        "UPDATE friend_requests SET status = 'accepted' WHERE id = $1 AND to_user = $2 AND status = 'pending' RETURNING *",
        [requestId, toId]
      );
      if (updateRes.rows.length === 0) {
        return socket.emit("error", { message: "申请不存在或已处理" });
      }
      await db.query(
        "INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING",
        [fromId, toId]
      );
      const fromSocket = onlineUsers.get(fromId);
      if (fromSocket) {
        io.to(fromSocket).emit("friend_accepted", { friendId: toId });
      }
      socket.emit("friend_accepted", { friendId: fromId });
      io.to(`user_${fromId}`).emit("friend_accepted");
      io.to(`user_${toId}`).emit("friend_accepted");
    } catch (err) {
      console.error("接受好友申请失败", err);
      socket.emit("error", { message: "服务器错误" });
    }
  });

  socket.on('private message', async (data, ack) => {
    if (!socket.userId) {
      if (typeof ack === 'function') ack({ success: false, error: '未登录' });
      return;
    }
    const now = Date.now();
    socket.msgTimestamps = socket.msgTimestamps.filter(t => now - t < 1000);
    if (socket.msgTimestamps.length >= 5) {
      if (typeof ack === 'function') ack({ success: false, error: '发送过快' });
      return;
    }
    socket.msgTimestamps.push(now);

    const { to, toType, type = 'text', content, fileName, duration, clientMsgId } = data;
    if (!to || !toType || !content?.trim()) {
      if (typeof ack === 'function') ack({ success: false, error: '数据不完整' });
      return;
    }

    if (clientMsgId && processedMsgIds.has(clientMsgId)) {
      if (typeof ack === 'function') ack({ success: true, duplicate: true });
      return;
    }

    if (toType === 'friend') {
      try {
        const friendCheck = await db.query(
          'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
          [socket.userId, parseInt(to)]
        );
        if (friendCheck.rows.length === 0) {
          if (typeof ack === 'function') ack({ success: false, error: '不是好友' });
          return;
        }
      } catch (err) {
        if (typeof ack === 'function') ack({ success: false, error: '服务器错误' });
        return;
      }

      try {
        const result = await db.query(
          `INSERT INTO messages (from_user, to_user, type, content, file_name, duration)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
          [socket.userId, parseInt(to), type, content.trim(), fileName || null, duration || null]
        );
        const msg = result.rows[0];
        io.to(`user_${socket.userId}`).emit('chat message', msg);
        io.to(`user_${to}`).emit('chat message', msg);
        if (clientMsgId) processedMsgIds.add(clientMsgId);
        if (typeof ack === 'function') ack({ success: true, msg });
      } catch (err) {
        if (typeof ack === 'function') ack({ success: false, error: '消息发送失败' });
      }
    } else if (toType === 'group') {
      try {
        const groupCheck = await db.query(
          'SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2',
          [parseInt(to), socket.userId]
        );
        if (groupCheck.rows.length === 0) {
          if (typeof ack === 'function') ack({ success: false, error: '不在群组中' });
          return;
        }
      } catch (err) {
        if (typeof ack === 'function') ack({ success: false, error: '服务器错误' });
        return;
      }

      try {
        const result = await db.query(
          `INSERT INTO messages (from_user, group_id, type, content, file_name, duration)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
          [socket.userId, parseInt(to), type, content.trim(), fileName || null, duration || null]
        );
        const msg = result.rows[0];
        const members = await db.query('SELECT user_id FROM group_members WHERE group_id = $1', [parseInt(to)]);
        members.rows.forEach(m => {
          io.to(`user_${m.user_id}`).emit('chat message', msg);
        });
        if (clientMsgId) processedMsgIds.add(clientMsgId);
        if (typeof ack === 'function') ack({ success: true, msg });
      } catch (err) {
        if (typeof ack === 'function') ack({ success: false, error: '消息发送失败' });
      }
    } else {
      if (typeof ack === 'function') ack({ success: false, error: '未知类型' });
    }
  });

  // WebRTC 信令
  socket.on('call_offer', (data) => {
    const { to, offer } = data;
    if (!to || !offer) return;
    io.to(`user_${to}`).emit('call_offer', { from: socket.userId, offer });
  });
  socket.on('call_answer', (data) => {
    const { to, answer } = data;
    if (!to || !answer) return;
    io.to(`user_${to}`).emit('call_answer', { from: socket.userId, answer });
  });
  socket.on('call_candidate', (data) => {
    const { to, candidate } = data;
    if (!to || !candidate) return;
    io.to(`user_${to}`).emit('call_candidate', { from: socket.userId, candidate });
  });
  socket.on('call_reject', (data) => {
    const { to } = data;
    if (!to) return;
    io.to(`user_${to}`).emit('call_rejected', { from: socket.userId });
  });
  socket.on('call_end', (data) => {
    const { to } = data;
    if (!to) return;
    io.to(`user_${to}`).emit('call_ended', { from: socket.userId });
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      console.log(`用户 ${socket.userId} 断开连接，当前在线用户数：${onlineUsers.size}`);
    }
  });
});

// ========== API 路由 ==========

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ success: true, service: 'qiaoqiaohua-backend', status: 'running' });
});

// 注册（已修复邀请码验证）
app.post('/api/register', async (req, res) => {
  const { username, password, nickname, inviteCode } = req.body;
  const trimmedPassword = password ? password.trim() : '';
  if (!username || !trimmedPassword) return res.json({ error: '信息不完整' });
  if (trimmedPassword.length < 8 || !/^(?=.*[a-zA-Z])(?=.*\d)/.test(trimmedPassword)) {
    return res.json({ error: '密码至少8位，且包含字母和数字' });
  }
  if (!/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{4,20}$/.test(username)) {
    return res.json({ error: '账号必须包含字母和数字，长度4-20位' });
  }

  try {
    const existing = await db.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.json({ error: '账号已存在' });
    }

    const userCount = await db.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCount.rows[0].count) > 0) {
      if (!inviteCode) return res.json({ error: '需要邀请码' });

      let codeValid = false;
      const codeCheck = await db.query('SELECT * FROM invite_codes WHERE code = $1', [inviteCode]);
      if (codeCheck.rows.length > 0) {
        const codeRow = codeCheck.rows[0];
        if (codeRow.is_permanent || codeRow.used_count < codeRow.max_uses) {
          await db.query('UPDATE invite_codes SET used_count = used_count + 1 WHERE id = $1', [codeRow.id]);
          codeValid = true;
        }
      } else {
        const userInvite = await db.query('SELECT id FROM users WHERE invite_code = $1', [inviteCode]);
        if (userInvite.rows.length > 0) {
          codeValid = true;
        }
      }

      if (!codeValid) return res.json({ error: '邀请码无效或已用完' });
    }

    const hashedPassword = await bcrypt.hash(trimmedPassword, 12);
    let finalNickname = sanitizeText((nickname || username).substring(0, 30));
    let newInviteCode;
    while (true) {
      newInviteCode = crypto.randomBytes(3).toString('hex').toUpperCase();
      const conflict = await db.query('SELECT 1 FROM users WHERE invite_code = $1', [newInviteCode]);
      if (conflict.rows.length === 0) break;
    }

    const result = await db.query(
      `INSERT INTO users (username, password, nickname, invite_code, invited_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, username, nickname, avatar, invite_code`,
      [username, hashedPassword, finalNickname, newInviteCode, inviteCode || null]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    res.json({ user: { id: user.id, username: user.username, nickname: user.nickname, avatar: user.avatar, inviteCode: user.invite_code } });
  } catch (err) {
    console.error(err);
    res.json({ error: '注册失败' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.json({ error: '账号或密码错误' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password || '', user.password);
    if (!valid) return res.json({ error: '账号或密码错误' });
    req.session.userId = user.id;
    res.json({ user: { id: user.id, username: user.username, nickname: user.nickname, avatar: user.avatar, inviteCode: user.invite_code } });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, username, nickname, avatar, chat_background, gender, region, signature, invite_code FROM users WHERE id = $1',
      [req.userId]
    );
    if (result.rows.length === 0) return res.json({ user: null });
    const u = result.rows[0];
    res.json({
      user: {
        id: u.id, username: u.username, nickname: u.nickname, avatar: u.avatar,
        chatBackground: u.chat_background, gender: u.gender, region: u.region,
        signature: u.signature, inviteCode: u.invite_code
      }
    });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/search', auth, searchLimiter, async (req, res) => {
  const q = req.query.q?.toLowerCase() || '';
  try {
    const result = await db.query(
      `SELECT id, username, nickname, avatar FROM users
       WHERE id != $1 AND privacy_allow_search = true
       AND (LOWER(username) LIKE $2 OR LOWER(nickname) LIKE $2)
       LIMIT 5`,
      [req.userId, `%${q}%`]
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '搜索失败' });
  }
});

app.get('/api/friends', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.username, u.nickname, u.avatar FROM users u
       JOIN friends f ON u.id = f.friend_id
       WHERE f.user_id = $1`,
      [req.userId]
    );
    res.json({ friends: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '获取好友列表失败' });
  }
});

app.post('/api/friend-request', auth, friendRequestLimiter, async (req, res) => {
  const { to, toUsername, message } = req.body;
  try {
    let target;
    if (to) {
      target = await db.query('SELECT id FROM users WHERE id = $1', [parseInt(to)]);
    } else {
      target = await db.query('SELECT id FROM users WHERE username = $1', [toUsername]);
    }
    if (target.rows.length === 0) return res.json({ error: '用户不存在' });
    const targetId = target.rows[0].id;

    const friendCheck = await db.query(
      'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
      [req.userId, targetId]
    );
    if (friendCheck.rows.length > 0) return res.json({ error: '已经是好友' });

    const pendingCheck = await db.query(
      'SELECT id FROM friend_requests WHERE from_user = $1 AND to_user = $2 AND status = $3',
      [req.userId, targetId, 'pending']
    );
    if (pendingCheck.rows.length > 0) return res.json({ error: '已发送过申请' });

    const pendingCount = await db.query(
      'SELECT COUNT(*) FROM friend_requests WHERE from_user = $1 AND status = $2',
      [req.userId, 'pending']
    );
    if (parseInt(pendingCount.rows[0].count) >= 100) {
      return res.json({ error: '待处理申请过多，请稍后再试' });
    }

    await db.query(
      `INSERT INTO friend_requests (from_user, to_user, message)
       VALUES ($1, $2, $3)`,
      [req.userId, targetId, message ? sanitizeText(message) : '请求添加好友']
    );

    const targetSid = onlineUsers.get(targetId);
    if (targetSid) {
      io.to(targetSid).emit('new_friend_request');
      io.to(targetSid).emit('friend_request_received', { fromId: req.userId, toId: targetId });
    }

    res.json({ message: '申请已发送' });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/add-by-invite', auth, async (req, res) => {
  const { inviteCode } = req.body;
  try {
    const targetRes = await db.query('SELECT id FROM users WHERE invite_code = $1', [inviteCode]);
    if (targetRes.rows.length === 0) return res.json({ error: '无效的邀请码' });
    const targetId = targetRes.rows[0].id;

    const friendCheck = await db.query(
      'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
      [req.userId, targetId]
    );
    if (friendCheck.rows.length > 0) return res.json({ error: '已经是好友' });

    const pendingCheck = await db.query(
      'SELECT id FROM friend_requests WHERE from_user = $1 AND to_user = $2 AND status = $3',
      [req.userId, targetId, 'pending']
    );
    if (pendingCheck.rows.length > 0) return res.json({ error: '已发送过申请' });

    const pendingCount = await db.query(
      'SELECT COUNT(*) FROM friend_requests WHERE from_user = $1 AND status = $2',
      [req.userId, 'pending']
    );
    if (parseInt(pendingCount.rows[0].count) >= 100) {
      return res.json({ error: '待处理申请过多，请稍后再试' });
    }

    const fromUser = await db.query('SELECT nickname, username FROM users WHERE id = $1', [req.userId]);
    const displayName = fromUser.rows[0].nickname || fromUser.rows[0].username;

    await db.query(
      `INSERT INTO friend_requests (from_user, to_user, message) VALUES ($1, $2, $3)`,
      [req.userId, targetId, `${displayName} 通过你的邀请码请求添加好友`]
    );
    await db.query(
      `INSERT INTO notifications (user_id, message) VALUES ($1, $2)`,
      [targetId, `用户 ${displayName} 通过邀请码添加了你`]
    );

    const targetSid = onlineUsers.get(targetId);
    if (targetSid) {
      io.to(targetSid).emit('new_friend_request');
      io.to(targetSid).emit('friend_request_received', { fromId: req.userId, toId: targetId });
    }

    res.json({ message: '好友申请已发送' });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.get('/api/friend-requests', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT fr.*, u1.username as from_username, u2.username as to_username
       FROM friend_requests fr
       JOIN users u1 ON fr.from_user = u1.id
       JOIN users u2 ON fr.to_user = u2.id
       WHERE fr.to_user = $1 OR fr.from_user = $1
       ORDER BY fr.created_at DESC`,
      [req.userId]
    );
    res.json({ requests: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/friend-request/:id/accept', auth, async (req, res) => {
  try {
    const reqObj = await db.query(
      'UPDATE friend_requests SET status = $1 WHERE id = $2 AND to_user = $3 AND status = $4 RETURNING *',
      ['accepted', req.params.id, req.userId, 'pending']
    );
    if (reqObj.rows.length === 0) return res.json({ error: '申请不存在或已处理' });

    const { from_user } = reqObj.rows[0];
    await db.query('INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING',
      [req.userId, from_user]);

    const fromSid = onlineUsers.get(from_user);
    if (fromSid) io.to(fromSid).emit('friend_accepted');
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/friend-request/:id/reject', auth, async (req, res) => {
  try {
    const reqObj = await db.query(
      'UPDATE friend_requests SET status = $1 WHERE id = $2 AND to_user = $3 AND status = $4 RETURNING *',
      ['rejected', req.params.id, req.userId, 'pending']
    );
    if (reqObj.rows.length === 0) return res.json({ error: '申请不存在或已处理' });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/friend-remove', auth, async (req, res) => {
  const { friendId } = req.body;
  const fid = parseInt(friendId);
  try {
    const friendCheck = await db.query(
      'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
      [req.userId, fid]
    );
    if (friendCheck.rows.length === 0) return res.json({ error: '不是好友' });

    await db.query('DELETE FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
      [req.userId, fid]);

    const userRes = await db.query('SELECT nickname, username FROM users WHERE id = $1', [req.userId]);
    const displayName = userRes.rows[0].nickname || userRes.rows[0].username;
    await db.query(
      'INSERT INTO notifications (user_id, message) VALUES ($1, $2)',
      [fid, `用户 ${displayName} 已将你从好友列表删除`]
    );

    const targetSid = onlineUsers.get(fid);
    if (targetSid) io.to(targetSid).emit('friend_removed');
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '服务器错误' });
  }
});

app.post('/api/groups', auth, async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length === 0) return res.json({ error: '群名称不能为空' });
  if (name.trim().length > 50) return res.json({ error: '群名称最多50个字符' });

  try {
    const groupCount = await db.query(
      'SELECT COUNT(*) FROM group_members WHERE user_id = $1',
      [req.userId]
    );
    if (parseInt(groupCount.rows[0].count) >= 50) return res.json({ error: '你已加入的群组过多（最多50个）' });

    const result = await db.query(
      'INSERT INTO groups (name, owner_id) VALUES ($1, $2) RETURNING *',
      [sanitizeText(name.trim()), req.userId]
    );
    const group = result.rows[0];
    await db.query('INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)',
      [group.id, req.userId, 'owner']);
    res.json({ group: { id: group.id, name: group.name } });
  } catch (err) {
    console.error(err);
    res.json({ error: '创建群组失败' });
  }
});

app.get('/api/groups', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT g.id, g.name FROM groups g
       JOIN group_members gm ON g.id = gm.group_id
       WHERE gm.user_id = $1`,
      [req.userId]
    );
    res.json({ groups: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '获取群组列表失败' });
  }
});

app.get('/api/messages/friend/:friendId', auth, async (req, res) => {
  const friendId = parseInt(req.params.friendId);
  try {
    const friendCheck = await db.query(
      'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
      [req.userId, friendId]
    );
    if (friendCheck.rows.length === 0) return res.json({ error: '不是好友' });

    const clearRes = await db.query(
      "SELECT COALESCE(cleared_timestamps->>$1, '0') as clear_time FROM users WHERE id = $2",
      [`friend_${friendId}`, req.userId]
    );
    const clearTime = parseInt(clearRes.rows[0].clear_time) || 0;

    const result = await db.query(
      `SELECT * FROM messages
       WHERE ((from_user = $1 AND to_user = $2) OR (from_user = $2 AND to_user = $1))
       AND to_user IS NOT NULL AND group_id IS NULL
       AND created_at > to_timestamp($3 / 1000.0)
       ORDER BY created_at ASC`,
      [req.userId, friendId, clearTime]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '获取消息失败' });
  }
});

app.get('/api/messages/group/:groupId', auth, async (req, res) => {
  const groupId = parseInt(req.params.groupId);
  try {
    const memberCheck = await db.query(
      'SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2',
      [groupId, req.userId]
    );
    if (memberCheck.rows.length === 0) return res.json({ error: '不在群组中' });

    const clearRes = await db.query(
      "SELECT COALESCE(cleared_timestamps->>$1, '0') as clear_time FROM users WHERE id = $2",
      [`group_${groupId}`, req.userId]
    );
    const clearTime = parseInt(clearRes.rows[0].clear_time) || 0;

    const result = await db.query(
      `SELECT * FROM messages
       WHERE group_id = $1
       AND created_at > to_timestamp($2 / 1000.0)
       ORDER BY created_at ASC`,
      [groupId, clearTime]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '获取消息失败' });
  }
});

app.post('/api/message/delete', auth, async (req, res) => {
  const { messageId } = req.body;
  try {
    const msgRes = await db.query('SELECT * FROM messages WHERE id = $1', [messageId]);
    if (msgRes.rows.length === 0) return res.json({ error: '消息不存在' });
    const msg = msgRes.rows[0];
    if (msg.from_user !== req.userId) return res.status(403).json({ error: '无权限' });

    if (msg.content && (msg.content.startsWith('/api/file/') || msg.content.startsWith('/uploads/'))) {
      const file = path.basename(msg.content);
      const filePath = path.join(UPLOAD_DIR, file);
      try { fs.unlinkSync(filePath); } catch(e) {}
    }

    await db.query('DELETE FROM messages WHERE id = $1', [messageId]);

    if (msg.to_user) {
      io.to(`user_${msg.from_user}`).emit('message_deleted', { messageId: msg.id });
      io.to(`user_${msg.to_user}`).emit('message_deleted', { messageId: msg.id });
    } else if (msg.group_id) {
      const members = await db.query('SELECT user_id FROM group_members WHERE group_id = $1', [msg.group_id]);
      members.rows.forEach(m => {
        io.to(`user_${m.user_id}`).emit('message_deleted', { messageId: msg.id });
      });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '删除失败' });
  }
});

app.post('/api/chat/clear', auth, async (req, res) => {
  const { chatType, chatId } = req.body;
  if (!chatType || !chatId) return res.json({ error: '参数错误' });
  const cid = parseInt(chatId);
  const now = Date.now();

  try {
    if (chatType === 'friend') {
      const friendCheck = await db.query(
        'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
        [req.userId, cid]
      );
      if (friendCheck.rows.length === 0) return res.json({ error: '不是好友' });

      const key = `friend_${cid}`;
      await db.query(
        `UPDATE users SET cleared_timestamps = jsonb_set(cleared_timestamps, $1, to_jsonb($2::text)) WHERE id = $3`,
        [`{${key}}`, now.toString(), req.userId]
      );
      io.to(`user_${req.userId}`).emit('chat_cleared', { chatType, chatId: cid });
    } else if (chatType === 'group') {
      const memberCheck = await db.query(
        'SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2',
        [cid, req.userId]
      );
      if (memberCheck.rows.length === 0) return res.json({ error: '无权操作' });

      const key = `group_${cid}`;
      await db.query(
        `UPDATE users SET cleared_timestamps = jsonb_set(cleared_timestamps, $1, to_jsonb($2::text)) WHERE id = $3`,
        [`{${key}}`, now.toString(), req.userId]
      );
      io.to(`user_${req.userId}`).emit('chat_cleared', { chatType, chatId: cid });
    } else {
      return res.json({ error: '未知类型' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '清空失败' });
  }
});

app.post('/api/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const newPwd = newPassword ? newPassword.trim() : '';
  if (newPwd.length < 8 || !/^(?=.*[a-zA-Z])(?=.*\d)/.test(newPwd)) {
    return res.json({ error: '新密码至少8位，且包含字母和数字' });
  }
  try {
    const userRes = await db.query('SELECT password FROM users WHERE id = $1', [req.userId]);
    const valid = await bcrypt.compare(oldPassword || '', userRes.rows[0].password);
    if (!valid) return res.json({ error: '旧密码错误' });
    const hash = await bcrypt.hash(newPwd, 12);
    await db.query('UPDATE users SET password = $1 WHERE id = $2', [hash, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '修改失败' });
  }
});

app.post('/api/avatar/upload', auth, (req, res) => {
  upload.single('avatar')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.json({ error: '文件过大' });
      return res.json({ error: err.message || '上传失败' });
    }
    if (!req.file) return res.json({ error: '未选择文件' });
    const ext = path.extname(req.file.originalname).toLowerCase().substring(1);
    const allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!allowed.includes(ext)) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '不支持的文件类型' });
    }
    if (!validateMagicNumber(req.file.path, ext)) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '文件内容不符合' });
    }
    if (req.file.size > 5 * 1024 * 1024) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '头像不能超过5MB' });
    }

    const url = `/api/file/${req.file.filename}`;
    try {
      await db.query('UPDATE users SET avatar = $1 WHERE id = $2', [url, req.userId]);
      await db.query('INSERT INTO uploaded_files (filename, owner_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.file.filename, req.userId]);
      fileOwners.set(req.file.filename, req.userId);
      res.json({ avatar: url });
    } catch (e) {
      console.error(e);
      fs.unlinkSync(req.file.path);
      res.json({ error: '更新头像失败' });
    }
  });
});

app.post('/api/background/upload', auth, (req, res) => {
  upload.single('background')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.json({ error: '文件过大' });
      return res.json({ error: err.message || '上传失败' });
    }
    if (!req.file) return res.json({ error: '未选择文件' });
    const ext = path.extname(req.file.originalname).toLowerCase().substring(1);
    const allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!allowed.includes(ext)) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '不支持的文件类型' });
    }
    if (req.file.size > 5 * 1024 * 1024) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '背景图片不能超过5MB' });
    }

    const url = `/api/file/${req.file.filename}`;
    try {
      await db.query('UPDATE users SET chat_background = $1 WHERE id = $2', [url, req.userId]);
      await db.query('INSERT INTO uploaded_files (filename, owner_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.file.filename, req.userId]);
      fileOwners.set(req.file.filename, req.userId);
      res.json({ chatBackground: url });
    } catch (e) {
      console.error(e);
      fs.unlinkSync(req.file.path);
      res.json({ error: '更新背景失败' });
    }
  });
});

app.post('/api/upload', auth, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.json({ error: '文件过大' });
      return res.json({ error: err.message || '上传失败' });
    }
    if (!req.file) return res.json({ error: '未选择文件' });

    const ext = path.extname(req.file.originalname).toLowerCase().substring(1);
    const typeInfo = ALLOWED_FILE_TYPES[ext];
    if (!typeInfo) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: '不支持的文件类型' });
    }
    if (req.file.size > typeInfo.maxSize) {
      fs.unlinkSync(req.file.path);
      return res.json({ error: `文件过大，${ext} 最大允许 ${Math.round(typeInfo.maxSize / 1024 / 1024)}MB` });
    }

    const needMagic = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'zip', 'mp3', 'mp4', 'webm', 'wav', 'ogg'];
    if (needMagic.includes(ext)) {
      if (!validateMagicNumber(req.file.path, ext)) {
        fs.unlinkSync(req.file.path);
        return res.json({ error: '文件内容与扩展名不符' });
      }
    }

    const url = `/api/file/${req.file.filename}`;
    try {
      await db.query('INSERT INTO uploaded_files (filename, owner_id) VALUES ($1, $2)',
        [req.file.filename, req.userId]);
      fileOwners.set(req.file.filename, req.userId);
      res.json({ url, originalName: req.file.originalname });
    } catch (e) {
      fs.unlinkSync(req.file.path);
      res.json({ error: '文件记录失败' });
    }
  });
});

app.get('/api/file/:name', auth, async (req, res) => {
  const filename = path.basename(req.params.name);
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: '文件不存在' });
  }

  try {
    const ownerCheck = await db.query('SELECT owner_id FROM uploaded_files WHERE filename = $1', [filename]);
    if (ownerCheck.rows.length > 0 && ownerCheck.rows[0].owner_id === req.userId) {
      return res.sendFile(filePath);
    }

    const userRes = await db.query('SELECT avatar, chat_background FROM users WHERE id = $1', [req.userId]);
    const user = userRes.rows[0];
    const fileUrl = `/api/file/${filename}`;
    if (user.avatar === fileUrl || user.chat_background === fileUrl) {
      return res.sendFile(filePath);
    }

    const msgCheck = await db.query(`
      SELECT m.id FROM messages m
      LEFT JOIN group_members gm ON m.group_id = gm.group_id AND gm.user_id = $2
      WHERE m.content = $1 OR m.content = $3
      AND (m.to_user = $2 OR m.from_user = $2 OR gm.user_id = $2)
      LIMIT 1
    `, [fileUrl, req.userId, `/uploads/${filename}`]);
    if (msgCheck.rows.length > 0) {
      return res.sendFile(filePath);
    }

    res.status(403).json({ error: '无权访问该文件' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC',
      [req.userId]
    );
    res.json({ notifications: result.rows });
  } catch (err) {
    console.error(err);
    res.json({ error: '获取通知失败' });
  }
});

app.post('/api/profile', auth, async (req, res) => {
  const { nickname, gender, region, signature } = req.body;
  try {
    const fields = {};
    if (nickname !== undefined) fields.nickname = sanitizeText(nickname).substring(0, 30);
    if (gender !== undefined) fields.gender = sanitizeText(gender).substring(0, 10);
    if (region !== undefined) fields.region = sanitizeText(region).substring(0, 30);
    if (signature !== undefined) fields.signature = sanitizeText(signature).substring(0, 200);

    if (Object.keys(fields).length > 0) {
      const setClauses = Object.keys(fields).map((key, i) => `${key} = $${i + 1}`);
      const values = Object.values(fields);
      await db.query(`UPDATE users SET ${setClauses.join(', ')} WHERE id = $${values.length + 1}`,
        [...values, req.userId]);
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ error: '更新资料失败' });
  }
});

app.post('/api/invite-codes', auth, async (req, res) => {
  const { max_uses, is_permanent } = req.body;
  try {
    let code;
    while (true) {
      code = crypto.randomBytes(4).toString('hex').toUpperCase();
      const conflict = await db.query('SELECT 1 FROM invite_codes WHERE code = $1', [code]);
      if (conflict.rows.length === 0) break;
    }
    await db.query(
      'INSERT INTO invite_codes (code, creator, is_permanent, max_uses) VALUES ($1, $2, $3, $4)',
      [code, req.userId, !!is_permanent, max_uses || 1]
    );
    res.json({ code });
  } catch (err) {
    console.error(err);
    res.json({ error: '生成邀请码失败' });
  }
});

app.get('/api/invite-codes/:code', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT code, is_permanent, max_uses, used_count FROM invite_codes WHERE code = $1',
      [req.params.code]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '邀请码不存在' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.json({ error: '查询失败' });
  }
});

// ========== 启动服务器 ==========
db.query('SELECT NOW()')
  .then(() => console.log('Neon Connected'))
  .catch(err => console.error('Neon 连接失败:', err));

initDB()
  .then(() => {
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      console.log(`悄悄话后端已启动，端口 ${PORT}`);
    });
  })
  .catch(err => {
    console.error('数据库初始化失败', err);
    process.exit(1);
  });
