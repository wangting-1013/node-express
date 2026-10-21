const http = require('http');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'my-secret-2026-fullstack-demo-abc123';
const PORT = 3000;

// 签发token
function generateToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.name, role: user.role },
    SECRET_KEY,
    { expiresIn: '2h' }
  )
}
// 校验token中间件
function verifyTokenMiddleware(token) {
  try {
    const info = jwt.verify(token, SECRET_KEY);
    return { valid: true, user: info };
  } catch (e) {
    return { valid: false, msg: e.message };
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  // 1. 登录接口 POST /login → 返回token
  if (req.method === 'POST' && req.url === '/login') {
    // 模拟校验账号密码，固定用户
    const mockUser = { id: 1001, name: 'zhangsan', role: 'user' };
    const token = generateToken(mockUser);
    res.writeHead(200);
    res.end(JSON.stringify({ token }));
    return;
  }

  // 2. 需要鉴权的接口 GET /api/profile
  if (req.method === 'GET' && req.url === '/api/profile') {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.writeHead(401);
      res.end(JSON.stringify({ msg: '缺少token' }));
      return;
    }
    // Bearer xxxxx
    const token = authHeader.split(' ')[1];
    const verifyResult = verifyTokenMiddleware(token);
    if (!verifyResult.valid) {
      res.writeHead(401);
      res.end(JSON.stringify({ msg: verifyResult.msg }));
      return;
    }
    // 校验成功，返回用户信息
    res.writeHead(200);
    res.end(JSON.stringify({
      msg: "认证成功",
      user: verifyResult.user
    }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({msg:"接口不存在"}));
})

server.listen(PORT, () => {
  console.log(`服务启动: http://127.0.0.1:${PORT}`)
})
