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

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'securepass',
  connectionLimit: 10
});

// Test database connection
console.log('🔄 Testing database connection...');
console.log('DB Config:', {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS ? '[HIDDEN]' : '[EMPTY]',
  database: process.env.DB_NAME || 'securepass'
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    console.error('Full error:', err);
  } else {
    console.log('✅ Database connected successfully!');
    connection.release();
  }
});

// helper: run query (promisified)
const db = pool.promise();

// Middleware: verify JWT
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Authorization required' });
  const token = header.split(' ')[1] || header; // allow "Bearer <token>" or token directly
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
}

// Encrypt / decrypt helpers using AES
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

// ---------- Auth ----------
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log('📝 Signup request received:', { name, email });

    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(400).json({ error: 'Email & password required' });
    }

    const hashed = bcrypt.hashSync(password, 10);
    console.log('🔐 Password hashed successfully');

    console.log('💾 Attempting to insert user into database...');
    await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name || '', email, hashed]);
    console.log('✅ User inserted successfully');

    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('❌ Signup error:', err);
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Email already exists' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('🔑 Login request received:', { email });

    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    console.log('📊 Query result:', rows.length, 'rows found');

    if (rows.length === 0) {
      console.log('❌ User not found');
      return res.status(404).json({ error: 'User not found' });
    }

    const user = rows[0];
    const valid = bcrypt.compareSync(password, user.password);
    console.log('🔓 Password validation:', valid ? 'SUCCESS' : 'FAILED');

    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '8h' });
    console.log('🎫 JWT token generated successfully');

    res.json({ message: 'Login success', token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    console.error('❌ Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Profile update endpoint
app.put('/update-profile', verifyToken, async (req, res) => {
  try {
    const { name } = req.body;
    console.log('👤 Profile update request received:', { userId: req.userId, name });

    // Validate input
    if (!name || name.trim().length === 0) {
      console.log('❌ Name is required');
      return res.status(400).json({ error: 'Name is required' });
    }

    // Update user name in database
    console.log('💾 Updating user profile in database...');
    const [result] = await db.query('UPDATE users SET name = ? WHERE id = ?', [name.trim(), req.userId]);

    if (result.affectedRows === 0) {
      console.log('❌ User not found or no changes made');
      return res.status(404).json({ error: 'User not found' });
    }

    // Fetch and return updated user data
    const [rows] = await db.query('SELECT id, name, email FROM users WHERE id = ?', [req.userId]);
    const updatedUser = rows[0];

    console.log('✅ Profile updated successfully:', updatedUser);
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('❌ Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Forgot password endpoint
app.post('/forgot-password', async (req, res) => {

// Create password entry (encrypt before save)
app.post('/passwords', verifyToken, async (req, res) => {
  try {
    const { title, username, password } = req.body;
    if (!title || !password) return res.status(400).json({ error: 'Title & password required' });
    const encrypted = encrypt(password);
    const [result] = await db.query('INSERT INTO passwords (user_id, title, username, password) VALUES (?, ?, ?, ?)', [req.userId, title, username || '', encrypted]);
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE id = ?', [result.insertId]);
    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all passwords (decrypt before return)
app.get('/passwords', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE user_id = ?', [req.userId]);
    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } 
});

// Update entry
app.put('/passwords/:id', verifyToken, async (req, res) => {
  try {
    const { title, username, password } = req.body;
    const encrypted = encrypt(password);
    await db.query('UPDATE passwords SET title=?, username=?, password=? WHERE id=? AND user_id=?', [title, username || '', encrypted, req.params.id, req.userId]);
    // Fetch and return the updated record with decrypted password
    const [rows] = await db.query('SELECT id, title, username, password, created_at, updated_at FROM passwords WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Password not found' });
    const decrypted = rows.map(r => ({ ...r, password: decrypt(r.password) }));
    res.json(decrypted[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete entry
app.delete('/passwords/:id', verifyToken, async (req, res) => {
  try {
    await db.query('DELETE FROM passwords WHERE id=? AND user_id=?', [req.params.id, req.userId]);
    res.json({ message: 'Deleted' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Server accessible at http://localhost:${PORT}`);
  console.log(`For network access, use your computer's IP address on port ${PORT}`);
});
