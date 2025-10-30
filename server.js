require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const AES_SECRET = process.env.AES_SECRET;

// ---------------- MySQL Connection Pool ----------------
// Works for both Local and Railway
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'securepass',
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  connectionLimit: 10,
  ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : false // SSL only for Railway
});

// ---------- Test DB Connection ----------
console.log('🔄 Testing database connection...');
console.log('DB Config:', {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS ? '[HIDDEN]' : '[EMPTY]',
  database: process.env.DB_NAME || 'securepass',
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully!');
    connection.release();
  }
});

const db = pool.promise();

// ---------------- JWT Middleware ----------------
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Authorization required' });
  const token = header.split(' ')[1] || header;
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
}

// ---------------- AES Encryption ----------------
function encrypt(text) {
  return CryptoJS.AES.encrypt(text, AES_SECRET).toString();
}

function decrypt(cipher) {
  try {
    const bytes = CryptoJS.AES.decrypt(cipher, AES_SECRET);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (e) {
    return null;
  }
}

// ---------------- Routes ----------------

// Root route
app.get('/', (req, res) => {
  res.send('🚀 Vaultify Backend is Running Successfully on Railway!');
});

// ---------- AUTH ----------
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email & password required' });

    const hashed = bcrypt.hashSync(password, 10);
    await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name || '', email, hashed]);
    res.json({ message: 'User registered' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0)
      return res.status(404).json({ error: 'User not found' });

    const user = rows[0];
    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ message: 'Login success', token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- PROFILE ----------
app.put('/update-profile', verifyToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || name.trim().length === 0)
      return res.status(400).json({ error: 'Name is required' });

    const [result] = await db.query('UPDATE users SET name = ? WHERE id = ?', [name.trim(), req.userId]);
    if (result.affectedRows === 0)
      return res.status(404).json({ error: 'User not found' });

    const [rows] = await db.query('SELECT id, name, email FROM users WHERE id = ?', [req.userId]);
    res.json({ success: true, message: 'Profile updated', user: rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.post('/forgot-password', async (req, res) => {
  res.json({ message: 'Forgot password endpoint not implemented yet' });
});

// ---------- PASSWORD MANAGEMENT ----------
app.post('/passwords', verifyToken, async (req, res) => {
  try {
    const { title, username, password } = req.body;
    if (!title || !password)
      return res.status(400).json({ error: 'Title & password required' });

    const encrypted = encrypt(password);
    const [result] = await db.query(
      'INSERT INTO passwords (user_id, title, username, password) VALUES (?, ?, ?, ?)',
      [req.userId, title, username || '', encrypted]
    );
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE id = ?', [result.insertId]);
    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/passwords', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE user_id = ?', [req.userId]);
    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/passwords/:id', verifyToken, async (req, res) => {
  try {
    const { title, username, password } = req.body;
    const encrypted = encrypt(password);
    await db.query('UPDATE passwords SET title=?, username=?, password=? WHERE id=? AND user_id=?', [title, username || '', encrypted, req.params.id, req.userId]);
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (rows.length === 0)
      return res.status(404).json({ error: 'Password not found' });

    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/passwords/:id', verifyToken, async (req, res) => {
  try {
    await db.query('DELETE FROM passwords WHERE id=? AND user_id=?', [req.params.id, req.userId]);
    res.json({ message: 'Deleted' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- SERVER START ----------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Local: http://localhost:${PORT}`);
});
// ---------- DELETE ACCOUNT ----------
app.delete('/delete-account', verifyToken, async (req, res) => {
  try {
    await db.query('DELETE FROM passwords WHERE user_id = ?', [req.userId]);
    const [result] = await db.query('DELETE FROM users WHERE id = ?', [req.userId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'Account and all associated data deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});