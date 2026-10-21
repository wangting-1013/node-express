// ！优先加载环境变量
// require('dotenv').config({
//   path: `.env.${process.env.NODE_ENV || 'development'}`
// });

const express = require('express');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');

// 从环境变量读取，不再写死
// const PORT = process.env.PORT;
// const SALT_ROUNDS = 10;
// const JWT_SECRET = process.env.JWT_SECRET;
// const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
// const DB_PATH = process.env.DB_PATH;

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;
// JWT密钥，生产环境不要硬编码，单独放环境变量
const JWT_SECRET = 'my-fullstack-secret-2026';
// token有效期 2小时
const JWT_EXPIRES_IN = '2h';

app.use(express.json());
// 打开数据库
const db = new Database('./mydb.db');
console.log('✅ SQLite(better-sqlite3) 连接成功');
db.pragma('journal_mode = WAL'); // SQLite 开启WAL，支持并发读，很重要！

// 创建users表
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

/**
 * 扣款接口 POST /api/deduct
 * 请求体：
 * {
 *   "idempotentKey": "客户端生成唯一uuid",
 *   "userId": 1,
 *   "amount": 20
 * }
 */
app.post('/api/deduct', (req, res, next) => {
  try {
    const { idempotentKey, userId, amount } = req.body;
    if (!idempotentKey || !userId || !amount) {
      return res.status(400).json({ code:400, msg:'参数缺失' });
    }

    // 1. 先查这个幂等key是否已经处理过
    const existRecord = db.prepare(`SELECT * FROM idempotent_record WHERE idempotent_key = ?`).get(idempotentKey);
    if (existRecord) {
      // 重复请求，直接返回上次结果，不扣款
      return res.json({ code:200, msg:'重复请求，已处理', data: JSON.parse(existRecord.result) });
    }

    // ========== 开启事务 原子扣款 ==========
    const tx = db.transaction((uid, num) => {
      // 悲观思路：先查询余额（在事务内）
      const row = db.prepare(`SELECT balance FROM account WHERE id = ?`).get(uid);
      if (!row) throw new Error('用户不存在');
      if (row.balance < num) throw new Error('余额不足');

      // 更新余额
      db.prepare(`UPDATE account SET balance = balance - ? WHERE id = ?`).run(num, uid);
      const newRow = db.prepare(`SELECT balance FROM account WHERE id = ?`).get(uid);
      return newRow.balance;
    });

    const newBalance = tx(userId, amount);

    // 扣款成功，写入幂等记录（打上标记，防止重试）
    const retData = { newBalance };
    db.prepare(`INSERT INTO idempotent_record(idempotent_key, result) VALUES (?, ?)`)
      .run(idempotentKey, JSON.stringify(retData));

    return res.json({ code:200, msg:'扣款成功', data: retData });

  } catch (err) {
    next(err);
  }
});


// ---------------------- JWT鉴权中间件（复用！订单接口后面也可以用） ----------------------
function authMiddleware(req, res, next) {
  // 取出Authorization请求头
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ code: 401, msg: '未提供token' });
  }
  // 截取Bearer后面的token字符串
  const token = authHeader.split(' ')[1];
  try {
    // 校验token，解析payload
    const payload = jwt.verify(token, JWT_SECRET);
    // 把用户信息挂载到req对象，后面接口直接使用
    req.user = payload;
    next(); // 放行，进入接口
  } catch (err) {
    return res.json({ code: 401, msg: 'token无效或已过期' });
  }
}

// ========== 注册接口 POST /api/register ==========
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    // 参数校验
    if (!username || !password) {
      return res.json({ code: 400, msg: '用户名和密码不能为空' });
    }
    if (username.length < 3) {
      return res.json({ code: 400, msg: '用户名至少3个字符' });
    }
    if (password.length < 6) {
      return res.json({ code: 400, msg: '密码至少6位' });
    }
    // 查询用户名是否存在
    const findUser = db.prepare(`SELECT id FROM users WHERE username = ?`);
    const row = findUser.get(username);
    if (row) {
      return res.json({ code: 400, msg: '用户名已被注册' });
    }
    // 密码哈希
    const hashPwd = await bcrypt.hash(password, SALT_ROUNDS);
    // 插入用户
    const insertStmt = db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`);
    const result = insertStmt.run(username, hashPwd);
    // result.lastInsertRowid 获取新增用户id（better-sqlite3 没有 lastID）
    res.json({
      code: 200,
      msg: '注册成功',
      data: {
        userId: Number(result.lastInsertRowid),
        username
      }
    });
  } catch (e) {
    console.error(e);
    res.json({ code: 500, msg: '服务器异常', error: e.message });
  }
});

// ========== 登录接口 POST /api/login ==========
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. 参数校验
    if (!username || !password) {
      return res.json({ code: 400, msg: '用户名和密码不能为空' });
    }

    // 2. 根据用户名查询用户（取出数据库存的hash密码）
    const queryUser = db.prepare(`SELECT id, username, password FROM users WHERE username = ?`);
    const user = queryUser.get(username);
    if (!user) {
      return res.json({ code: 400, msg: '用户名不存在' });
    }

    // 3. 比对密码：明文password 和数据库里面的hash密码
    const isPwdOk = await bcrypt.compare(password, user.password);
    if (!isPwdOk) {
      return res.json({ code: 400, msg: '密码错误' });
    }

    // 4. 签发JWT token，payload放用户id、用户名（不要放密码！）
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // 5. 返回token
    res.json({
      code: 200,
      msg: '登录成功',
      data: {
        token,
        userId: user.id,
        username: user.username
      }
    });

  } catch (e) {
    console.error(e);
    res.json({ code: 500, msg: '服务器异常', error: e.message });
  }
});
// ========== 登录接口 GET /api/getUserInfo ==========
app.get('/api/getUserInfo',authMiddleware,async (req, res)=>{
  try {
    // req.user 是中间件解析token之后挂载的，里面有userId
    const userId = req.user.userId;
    // 查询用户，不查password！
    const getUserStmt = db.prepare(`SELECT id, username, created_at FROM users WHERE id = ?`);
    const userInfo = getUserStmt.get(userId);

    if (!userInfo) {
      return res.json({ code: 404, msg: '用户不存在' });
    }
    res.json({
      code: 200,
      msg: '获取成功',
      data: userInfo
    });
  } catch (e) {
    console.error(e);
    res.json({ code: 500, msg: '服务器异常', error: e.message });
  }

})

app.get('/', (req, res) => {
  res.send('Hello Fullstack');
});

// ---------------------- 404 路由不存在中间件 ----------------------
app.use((req, res) => {
  res.status(404).json({ code: 404, msg: '接口不存在' });
});

// ---------------------- 全局统一错误处理中间件（必须放在所有路由最后！4个参数不能少） ----------------------
app.use((err, req, res, next) => {
  console.error('服务器异常：', err);
  // 默认500错误
  res.status(500).json({
    code: 500,
    msg: '服务器内部错误',
    error: err.message
  });
});

const server = app.listen(PORT, () => {
  console.log(`服务启动 http://127.0.0.1:${PORT}`);
});

// 启动失败时把原因打出来，避免命令行「静默无输出」
server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ 启动失败：端口 ${PORT} 已被占用。`);
    console.error(`   请先用 netstat -ano | findstr :${PORT} 找到占用进程并结束，或修改本文件里的 PORT。`);
  } else if (err.code === 'EACCES') {
    console.error(`❌ 启动失败：没有权限监听端口 ${PORT}，请换一个 1024 以上的端口。`);
  } else {
    console.error('❌ 服务启动失败：', err);
  }
  process.exit(1);
});