const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Cho phép fetch từ userscript (browser)

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL + "?sslmode=require",
});

// Tạo table nếu chưa có (chạy tự động khi start)
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      key TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expiration TIMESTAMP
    );
  `);
}
initDb().catch(console.error);

// POST /add-key: Thêm key mới (bảo vệ bằng secret, ví dụ: admin_secret = 'your_secret_here')
app.post('/add-key', async (req, res) => {
  const { key, type, admin_secret } = req.body;
  if (admin_secret !== 'your_secret_here') { // Thay bằng secret của bạn
    return res.status(403).json({ error: 'Unauthorized' });
  }
  if (!key || !['hour', 'day', 'month', 'lifetime'].includes(type)) {
    return res.status(400).json({ error: 'Invalid key or type' });
  }

  let expiration = null;
  const now = new Date();
  if (type === 'hour') {
    expiration = new Date(now.getTime() + 60 * 60 * 1000); // +1 giờ
  } else if (type === 'day') {
    expiration = new Date(now.getTime() + 24 * 60 * 60 * 1000); // +1 ngày
  } else if (type === 'month') {
    expiration = new Date(now.setMonth(now.getMonth() + 1)); // +1 tháng
  } // lifetime: null

  try {
    await pool.query(
      'INSERT INTO keys (key, type, expiration) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING',
      [key, type, expiration]
    );
    res.json({ success: true, message: 'Key added' });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /verify-key: Kiểm tra key
app.post('/verify-key', async (req, res) => {
  const { key } = req.body;
  if (!key) {
    return res.status(400).json({ error: 'Key required' });
  }

  try {
    const result = await pool.query('SELECT expiration FROM keys WHERE key = $1', [key]);
    if (result.rows.length === 0) {
      return res.json({ valid: false, message: 'Invalid key' });
    }

    const expiration = result.rows[0].expiration;
    if (expiration && new Date(expiration) < new Date()) {
      return res.json({ valid: false, message: 'Key expired' });
    }

    res.json({ valid: true, message: 'Key valid' });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));

module.exports = app; // Cho Vercel