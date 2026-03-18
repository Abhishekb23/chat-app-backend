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

    await query(
      `
      INSERT INTO conversation_members (conversation_id, user_id, role)
      VALUES ($1, $2, 'OWNER')
      `,
      [conversationId, myId]
    );

    if (Array.isArray(memberIds)) {
      for (const id of memberIds) {
        const uid = Number(id);

        if (!uid || uid === myId) continue;

        await query(
          `
          INSERT INTO conversation_members (conversation_id, user_id, role)
          VALUES ($1, $2, 'MEMBER')
          ON CONFLICT (conversation_id, user_id) DO NOTHING
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

// ADD MEMBERS TO EXISTING GROUP
router.post("/:groupId/members", auth, async (req, res) => {
  try {
    const groupId = Number(req.params.groupId);
    const myId = Number(req.user.id);
    const memberIds = Array.isArray(req.body.memberIds) ? req.body.memberIds : [];

    if (!groupId) {
      return res.status(400).json({ message: "Invalid group id" });
    }

    const groupCheck = await query(
      `
      SELECT c.id, c.type, cm.role
      FROM conversations c
      JOIN conversation_members cm
        ON c.id = cm.conversation_id
      WHERE c.id = $1
        AND c.type = 'GROUP'
        AND cm.user_id = $2
      LIMIT 1
      `,
      [groupId, myId]
    );

    if (groupCheck.rows.length === 0) {
      return res.status(404).json({ message: "Group not found or access denied" });
    }

    const role = groupCheck.rows[0].role;

    if (!["OWNER", "ADMIN"].includes(role)) {
      return res.status(403).json({ message: "Only owner or admin can add members" });
    }

    for (const rawId of memberIds) {
      const uid = Number(rawId);

      if (!uid || uid === myId) continue;

      await query(
        `
        INSERT INTO conversation_members (conversation_id, user_id, role)
        VALUES ($1, $2, 'MEMBER')
        ON CONFLICT (conversation_id, user_id) DO NOTHING
        `,
        [groupId, uid]
      );
    }

    res.json({
      success: true,
      message: "Members added successfully",
    });
  } catch (err) {
    console.error("ADD MEMBERS ERROR:", err);
    res.status(500).json({ message: "Failed to add members" });
  }
});

module.exports = router;