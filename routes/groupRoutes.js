const express = require("express");
const { query } = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

// CREATE GROUP
router.post("/", auth, async (req, res) => {
  try {
    const { name, memberIds } = req.body;
    const myId = Number(req.user.id);

    if (!name || !name.trim()) {
      return res.status(400).json({ message: "Group name required" });
    }

    const conv = await query(
      `
      INSERT INTO conversations (type, name, created_by)
      VALUES ('GROUP', $1, $2)
      RETURNING *
      `,
      [name.trim(), myId]
    );

    const conversationId = conv.rows[0].id;

    // add owner
    await query(
      `
      INSERT INTO conversation_members(conversation_id,user_id,role)
      VALUES($1,$2,'OWNER')
      `,
      [conversationId, myId]
    );

    // add members
    if (Array.isArray(memberIds)) {
      for (const id of memberIds) {
        const uid = Number(id);

        if (!uid || uid === myId) continue;

        await query(
          `
          INSERT INTO conversation_members(conversation_id,user_id,role)
          VALUES($1,$2,'MEMBER')
          ON CONFLICT DO NOTHING
          `,
          [conversationId, uid]
        );
      }
    }

    res.json({
      success: true,
      conversation: conv.rows[0],
    });
  } catch (err) {
    console.error("GROUP CREATE ERROR:", err);
    res.status(500).json({ message: "Group creation failed" });
  }
});

module.exports = router;