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
app.use(express.json());

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
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) return res.status(400).json({ message: "Username and password are required." });

    const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) return res.status(400).json({ message: "Username already exists." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully.", user: newUser.rows[0] });
  } catch (err) {
    console.error("❌ Register error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) return res.status(400).json({ message: "Username and password are required." });

    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0) return res.status(400).json({ message: "Invalid username or password." });

    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) return res.status(400).json({ message: "Invalid username or password." });

    const token = jwt.sign(
      { id: user.rows[0].id, username: user.rows[0].username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, user: { id: user.rows[0].id, username: user.rows[0].username } });
  } catch (err) {
    console.error("❌ Login error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

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
app.post('/api/messages/send', authenticateToken, async (req, res) => {
  const { receiver_id, message } = req.body;
  try {
    if (!receiver_id || !message) return res.status(400).json({ message: "Receiver ID and message are required." });

    const newMessage = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, receiver_id, message]
    );

    res.status(201).json({ message: "Message sent successfully.", data: newMessage.rows[0] });
  } catch (err) {
    console.error("❌ Send message error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.get('/api/messages/conversation/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  try {
    const chatHistory = await pool.query(
      `SELECT m.id, m.sender_id, s.username AS sender_name,
              m.receiver_id, r.username AS receiver_name,
              m.message,
              TO_CHAR(m.created_at, 'YYYY-MM-DD') AS sent_date,
              TO_CHAR(m.created_at, 'HH12:MI AM') AS sent_time
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

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const msg = await pool.query('SELECT * FROM messages WHERE id = $1', [id]);
    if (msg.rows.length === 0) return res.status(404).json({ message: "Message not found" });
    if (msg.rows[0].sender_id !== req.user.id) return res.status(403).json({ message: "You can only delete your own messages." });

    await pool.query('DELETE FROM messages WHERE id = $1', [id]);
    res.json({ message: "Message deleted successfully.", id });
  } catch (err) {
    console.error("❌ Delete message error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ==========================
// GROUP ROUTES
// ==========================
app.post('/api/groups', authenticateToken, async (req, res) => {
  const { name, members } = req.body;
  try {
    const group = await pool.query(
      `INSERT INTO groups (name, created_by) VALUES ($1, $2) RETURNING *`,
      [name, req.user.id]
    );

    // Add creator + members
    await pool.query(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, [group.rows[0].id, req.user.id]);
    for (let m of members) {
      await pool.query(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, [group.rows[0].id, m]);
    }

    res.json(group.rows[0]);
  } catch (err) {
    console.error("❌ Create group error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await pool.query(
      `SELECT g.* 
       FROM groups g
       JOIN group_members gm ON g.id = gm.group_id
       WHERE gm.user_id = $1`,
      [req.user.id]
    );
    res.json(groups.rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// -------- ADD MEMBERS TO EXISTING GROUP --------
app.post('/api/groups/:groupId/add-members', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { members } = req.body; // array of user IDs

  try {
    // Check if group exists
    const group = await pool.query('SELECT * FROM groups WHERE id = $1', [groupId]);
    if (group.rows.length === 0) return res.status(404).json({ message: "Group not found" });

    // Add new members, avoid duplicates
    for (let m of members) {
      const exists = await pool.query('SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, m]);
      if (exists.rows.length === 0) {
        await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)', [groupId, m]);
      }
    }

    const updatedMembers = await pool.query(
      `SELECT u.id, u.username
       FROM users u
       JOIN group_members gm ON u.id = gm.user_id
       WHERE gm.group_id = $1`,
      [groupId]
    );

    res.json({ message: "Members added successfully", members: updatedMembers.rows });
  } catch (err) {
    console.error("❌ Add members error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// -------- GROUP MESSAGES --------
app.post('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { message } = req.body;

  try {
   const newMessage = await pool.query(
  `INSERT INTO group_messages (group_id, sender_id, message) 
   VALUES ($1, $2, $3) 
   RETURNING *`,
  [groupId, req.user.id, message]
);
    res.json(newMessage.rows[0]);
  } catch (err) {
    console.error("❌ Send group message error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  try {
   const messages = await pool.query(
  `SELECT gm.*, u.username AS sender_name
   FROM group_messages gm
   JOIN users u ON gm.sender_id = u.id
   WHERE gm.group_id = $1
   ORDER BY gm.created_at ASC`,
  [req.params.groupId]
);

    res.json(messages.rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});


// DELETE group message
app.delete('/api/groups/:groupId/messages/:msgId', authenticateToken, async (req, res) => {
  const { groupId, msgId } = req.params;
  try {
    const msg = await pool.query(
      'SELECT * FROM group_messages WHERE id = $1 AND group_id = $2',
      [msgId, groupId]
    );

    if (msg.rows.length === 0)
      return res.status(404).json({ message: "Message not found" });

    if (msg.rows[0].sender_id !== req.user.id)
      return res.status(403).json({ message: "You can only delete your own messages." });

    await pool.query('DELETE FROM group_messages WHERE id = $1', [msgId]);
    res.json({ message: "Group message deleted successfully", id: msgId });
  } catch (err) {
    console.error("❌ Delete group message error:", err.message);
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
