const axios = require('axios');
const { v4: uuidv4 } = require('uuid'); // 这一行就是你漏掉的！

async function req(key) {
  return axios.post('http://localhost:3000/api/deduct', {
    idempotentKey: key,
    userId: 1,
    amount: 20
  }).then(r=>console.log(r.data)).catch(e=>console.log(e.response.data));
}

// 并发两个不同幂等key，模拟同时扣款
Promise.all([
  req(uuidv4()),
  req(uuidv4())
])
