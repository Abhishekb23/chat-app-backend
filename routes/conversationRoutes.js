const express = require("express");
const { query } = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

/*
-----------------------------------------
Create or Get Direct Conversation
-----------------------------------------
*/
router.post("/direct", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);
    const otherUserId = parseInt(req.body.userId);

    if (!otherUserId) {
      return res.status(400).json({ message: "userId is required" });
    }

    if (myId === otherUserId) {
      return res.status(400).json({ message: "You cannot chat with yourself" });
    }

    // Check user exists
    const userExists = await query(
      `SELECT id FROM users WHERE id = $1::int`,
      [otherUserId]
    );

    if (userExists.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check existing conversation
    const existing = await query(
      `
      SELECT conversation_id
      FROM direct_conversations
      WHERE LEAST(user1_id, user2_id) = LEAST($1::int, $2::int)
      AND GREATEST(user1_id, user2_id) = GREATEST($1::int, $2::int)
      LIMIT 1
      `,
      [myId, otherUserId]
    );

    if (existing.rows.length > 0) {
      return res.json({
        success: true,
        conversationId: existing.rows[0].conversation_id
      });
    }

    // Create conversation
    const conv = await query(
      `
      INSERT INTO conversations(type, created_by)
      VALUES ('DIRECT', $1::int)
      RETURNING id
      `,
      [myId]
    );

    const conversationId = conv.rows[0].id;

    // Add members
    await query(
      `
      INSERT INTO conversation_members(conversation_id, user_id, role)
      VALUES
        ($1::int, $2::int, 'OWNER'),
        ($1::int, $3::int, 'MEMBER')
      `,
      [conversationId, myId, otherUserId]
    );

    // Save pair
    await query(
      `
      INSERT INTO direct_conversations(conversation_id, user1_id, user2_id)
      VALUES ($1::int, LEAST($2::int,$3::int), GREATEST($2::int,$3::int))
      `,
      [conversationId, myId, otherUserId]
    );

    res.status(201).json({
      success: true,
      conversationId
    });

  } catch (err) {
    console.error("DIRECT CHAT ERROR:", err);
    res.status(500).json({ message: "Direct chat error" });
  }
});

/*
-----------------------------------------
Get User Conversations
-----------------------------------------
*/
router.get("/", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);

    const result = await query(
      `
      SELECT
        c.id,
        c.type,
        c.name,
        c.updated_at,

        CASE
          WHEN c.type='DIRECT' AND dc.user1_id=$1::int THEN u2.username
          WHEN c.type='DIRECT' AND dc.user2_id=$1::int THEN u1.username
          ELSE c.name
        END AS display_name,

        (
          SELECT m.content
          FROM messages m
          WHERE m.conversation_id=c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message,

        (
          SELECT m.created_at
          FROM messages m
          WHERE m.conversation_id=c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message_at

      FROM conversations c
      JOIN conversation_members cm
        ON c.id = cm.conversation_id

      LEFT JOIN direct_conversations dc
        ON dc.conversation_id = c.id

      LEFT JOIN users u1
        ON dc.user1_id = u1.id

      LEFT JOIN users u2
        ON dc.user2_id = u2.id

      WHERE cm.user_id = $1::int

      ORDER BY COALESCE(
        (
          SELECT m.created_at
          FROM messages m
          WHERE m.conversation_id=c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ),
        c.updated_at
      ) DESC
      `,
      [myId]
    );

    const conversations = result.rows.map(row => ({
      id: row.id,
      type: row.type,
      name: row.display_name || row.name || "Direct Chat",
      last_message: row.last_message || "",
      last_message_at: row.last_message_at || row.updated_at
    }));

    res.json({
      success: true,
      conversations
    });

  } catch (err) {
    console.error("GET CONVERSATIONS ERROR:", err);
    res.status(500).json({ message: "Conversation fetch error" });
  }
});

module.exports = router;