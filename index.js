// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ==========================
// DATABASE CONNECTION
// ==========================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL Database"))
  .catch(err => console.error("❌ Database connection error:", err));

// ==========================
// EXPRESS APP SETUP
// ==========================
const app = express();
app.use(cors());
app.use(express.json()); // Parse JSON body

// ==========================
// JWT MIDDLEWARE
// ==========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token." });
    req.user = user;
    next();
  });
};

// ==========================
// ROOT ENDPOINT
// ==========================
app.get('/', (req, res) => {
  res.send('🚀 Chat App API is running...');
});

// ==========================
// USER ROUTES
// ==========================

// -------- REGISTER --------
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }

    const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Username already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.status(201).json({
      message: "User registered successfully.",
      user: newUser.rows[0]
    });
  } catch (err) {
    console.error("❌ Register error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// -------- LOGIN --------
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }

    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, username: user.rows[0].username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: { id: user.rows[0].id, username: user.rows[0].username }
    });
  } catch (err) {
    console.error("❌ Login error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// -------- SEARCH USERS --------
app.get('/api/auth/search', authenticateToken, async (req, res) => {
  const { query } = req.query;
  try {
    const users = await pool.query(
      'SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2',
      [`%${query}%`, req.user.id]
    );
    res.json(users.rows);
  } catch (err) {
    console.error("❌ Search error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// MESSAGE ROUTES
// ==========================

// -------- SEND MESSAGE --------
app.post('/api/messages/send', authenticateToken, async (req, res) => {
  const { receiver_id, message } = req.body;

  try {
    if (!receiver_id || !message) {
      return res.status(400).json({ message: "Receiver ID and message are required." });
    }

    const newMessage = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, receiver_id, message]
    );

    res.status(201).json({
      message: "Message sent successfully.",
      data: newMessage.rows[0]
    });
  } catch (err) {
    console.error("❌ Send message error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// -------- FETCH CHAT HISTORY --------
app.get('/api/messages/conversation/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;

  try {
    const chatHistory = await pool.query(
      `SELECT m.id, m.sender_id, s.username AS sender_name,
              m.receiver_id, r.username AS receiver_name,
              m.message, m.created_at
       FROM messages m
       JOIN users s ON m.sender_id = s.id
       JOIN users r ON m.receiver_id = r.id
       WHERE (m.sender_id = $1 AND m.receiver_id = $2)
          OR (m.sender_id = $2 AND m.receiver_id = $1)
       ORDER BY m.created_at ASC`,
      [req.user.id, userId]
    );

    res.json(chatHistory.rows);
  } catch (err) {
    console.error("❌ Fetch chat history error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// START SERVER
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
