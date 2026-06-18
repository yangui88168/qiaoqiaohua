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

// ========== 目录与持久化配置（保留 JSON 双保存） ==========
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');

let users = new Map();
const usernameIndex = new Map();
const inviteIndex = new Map();
const fileOwners = new Map();        // 内存备份（实际权限以 uploaded_files 表为准）
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

// 启动时加载 JSON 备份
loadData();
// 每 30 秒自动保存 JSON 备份
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
    tableName: 'session'
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

// ...（其余原有代码保持不变，包括 ALLOWED_FILE_TYPES、multer 配置、validateMagicNumber 等）

// ========== 在线用户 Map ==========
const onlineUsers = new Map();

// ========== 数据库初始化建表 ==========
async function initDB() {
  // ...（同原代码，创建 users、friend_requests 等所有表）
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

// ========== Socket.IO 配置（保持不变） ==========
// ... 完整 socket 逻辑同原代码

// ========== API 路由 ==========
// ... 所有 API（/api/register、/api/login、好友、群组、消息等）保持不变，直接操作 PostgreSQL

// ========== 启动服务器 ==========
// 先测试 Neon 连接
db.query('SELECT NOW()')
  .then(() => console.log('Neon Connected'))
  .catch(err => console.error('Neon 连接失败:', err));

// 初始化数据库表并启动
initDB()
  .then(() => {
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('数据库初始化失败', err);
    process.exit(1);
  });
