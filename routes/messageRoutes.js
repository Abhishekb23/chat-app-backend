const express = require("express");
const fs = require("fs");
const path = require("path");
const { query } = require("../config/db");
const auth = require("../middleware/auth");
const upload = require("../middleware/upload");

const router = express.Router();

/*
-----------------------------------------
Get messages of a conversation
-----------------------------------------
*/
router.get("/conversations/:conversationId/messages", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);
    const conversationId = parseInt(req.params.conversationId);

    if (!conversationId) {
      return res.status(400).json({ message: "Invalid conversation id" });
    }

    const access = await query(
      `
      SELECT 1
      FROM conversation_members
      WHERE conversation_id = $1::int
        AND user_id = $2::int
      LIMIT 1
      `,
      [conversationId, myId]
    );

    if (access.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const result = await query(
      `
      SELECT
        m.id,
        m.conversation_id,
        m.sender_id,
        u.username AS sender_name,
        CASE
          WHEN m.is_deleted = true THEN 'This message was deleted'
          ELSE m.content
        END AS content,
        m.message_type,
        m.is_edited,
        m.is_deleted,
        m.created_at,
        m.updated_at,
        mf.file_url,
        mf.original_name,
        mf.mime_type,
        mf.file_size
      FROM messages m
      JOIN users u ON u.id = m.sender_id
      LEFT JOIN message_files mf ON mf.message_id = m.id
      WHERE m.conversation_id = $1::int
      ORDER BY m.created_at ASC
      `,
      [conversationId]
    );

    res.json({
      success: true,
      messages: result.rows,
    });
  } catch (err) {
    console.error("GET MESSAGES ERROR:", err);
    res.status(500).json({ message: "Fetch messages error" });
  }
});

/*
-----------------------------------------
Send text message
-----------------------------------------
*/
router.post("/messages", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);
    const conversationId = parseInt(req.body.conversationId);
    const content = String(req.body.content || "").trim();

    if (!conversationId || !content) {
      return res.status(400).json({
        message: "conversationId and content are required",
      });
    }

    const access = await query(
      `
      SELECT 1
      FROM conversation_members
      WHERE conversation_id = $1::int
        AND user_id = $2::int
      LIMIT 1
      `,
      [conversationId, myId]
    );

    if (access.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const inserted = await query(
      `
      INSERT INTO messages (conversation_id, sender_id, content, message_type)
      VALUES ($1::int, $2::int, $3, 'TEXT')
      RETURNING id
      `,
      [conversationId, myId, content]
    );

    await query(
      `
      UPDATE conversations
      SET updated_at = CURRENT_TIMESTAMP
      WHERE id = $1::int
      `,
      [conversationId]
    );

    const msg = await query(
      `
      SELECT
        m.id,
        m.conversation_id,
        m.sender_id,
        u.username AS sender_name,
        m.content,
        m.message_type,
        m.is_edited,
        m.is_deleted,
        m.created_at,
        m.updated_at,
        NULL AS file_url,
        NULL AS original_name,
        NULL AS mime_type,
        NULL AS file_size
      FROM messages m
      JOIN users u ON u.id = m.sender_id
      WHERE m.id = $1::int
      `,
      [inserted.rows[0].id]
    );

    const io = req.app.get("io");
    io.to(`conversation_${conversationId}`).emit("receive_message", msg.rows[0]);

    res.status(201).json({
      success: true,
      message: msg.rows[0],
    });
  } catch (err) {
    console.error("SEND MESSAGE ERROR:", err);
    res.status(500).json({ message: "Send message error" });
  }
});

/*
-----------------------------------------
Upload and send file
-----------------------------------------
*/
router.post("/messages/upload", auth, upload.single("file"), async (req, res) => {
  try {
    const senderId = Number(req.user.id);
    const conversationId = Number(req.body.conversationId);

    if (!conversationId) {
      return res.status(400).json({ message: "conversationId is required" });
    }

    if (!req.file) {
      return res.status(400).json({ message: "File is required" });
    }

    const access = await query(
      `
      SELECT 1
      FROM conversation_members
      WHERE conversation_id = $1::int
        AND user_id = $2::int
      LIMIT 1
      `,
      [conversationId, senderId]
    );

    if (access.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    const messageType = req.file.mimetype.startsWith("image/")
      ? "IMAGE"
      : "FILE";

    const messageResult = await query(
      `
      INSERT INTO messages (conversation_id, sender_id, content, message_type)
      VALUES ($1::int, $2::int, $3, $4)
      RETURNING id
      `,
      [conversationId, senderId, req.file.originalname, messageType]
    );

    const messageId = messageResult.rows[0].id;
    const fileUrl = `/uploads/${req.file.filename}`;

    await query(
      `
      INSERT INTO message_files (
        message_id,
        file_name,
        original_name,
        file_url,
        mime_type,
        file_size
      )
      VALUES ($1::int, $2, $3, $4, $5, $6)
      `,
      [
        messageId,
        req.file.filename,
        req.file.originalname,
        fileUrl,
        req.file.mimetype,
        req.file.size,
      ]
    );

    await query(
      `
      UPDATE conversations
      SET updated_at = CURRENT_TIMESTAMP
      WHERE id = $1::int
      `,
      [conversationId]
    );

    const fullMessage = await query(
      `
      SELECT
        m.id,
        m.conversation_id,
        m.sender_id,
        u.username AS sender_name,
        m.content,
        m.message_type,
        m.is_edited,
        m.is_deleted,
        m.created_at,
        m.updated_at,
        mf.file_url,
        mf.original_name,
        mf.mime_type,
        mf.file_size
      FROM messages m
      JOIN users u ON u.id = m.sender_id
      LEFT JOIN message_files mf ON mf.message_id = m.id
      WHERE m.id = $1::int
      `,
      [messageId]
    );

    const io = req.app.get("io");
    io.to(`conversation_${conversationId}`).emit(
      "receive_message",
      fullMessage.rows[0]
    );

    res.status(201).json({
      success: true,
      message: fullMessage.rows[0],
    });
  } catch (err) {
    console.error("FILE UPLOAD ERROR:", err);
    res.status(500).json({ message: "File upload failed" });
  }
});

/*
-----------------------------------------
Edit message
-----------------------------------------
*/
router.patch("/messages/:id", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);
    const id = parseInt(req.params.id);
    const content = String(req.body.content || "").trim();

    if (!content) {
      return res.status(400).json({ message: "Updated content is required" });
    }

    const existing = await query(
      `SELECT * FROM messages WHERE id = $1::int`,
      [id]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ message: "Message not found" });
    }

    const message = existing.rows[0];

    if (parseInt(message.sender_id) !== myId) {
      return res.status(403).json({
        message: "You can edit only your own message",
      });
    }

    if (message.is_deleted) {
      return res.status(400).json({
        message: "Deleted message cannot be edited",
      });
    }

    if (message.message_type !== "TEXT") {
      return res.status(400).json({
        message: "Only text messages can be edited",
      });
    }

    const updated = await query(
      `
      UPDATE messages
      SET content = $1,
          is_edited = true,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $2::int
      RETURNING *
      `,
      [content, id]
    );

    res.json({
      success: true,
      message: updated.rows[0],
    });
  } catch (err) {
    console.error("EDIT MESSAGE ERROR:", err);
    res.status(500).json({ message: "Edit message error" });
  }
});

/*
-----------------------------------------
Delete message
-----------------------------------------
*/
router.delete("/messages/:id", auth, async (req, res) => {
  try {
    const myId = parseInt(req.user.id);
    const id = parseInt(req.params.id);

    const existing = await query(
      `
      SELECT
        m.*,
        mf.file_name
      FROM messages m
      LEFT JOIN message_files mf ON mf.message_id = m.id
      WHERE m.id = $1::int
      `,
      [id]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ message: "Message not found" });
    }

    const message = existing.rows[0];

    if (parseInt(message.sender_id) !== myId) {
      return res.status(403).json({
        message: "You can delete only your own message",
      });
    }

    await query(
      `
      UPDATE messages
      SET is_deleted = true,
          content = '',
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1::int
      `,
      [id]
    );

    if (message.file_name) {
      const filePath = path.join(__dirname, "..", "uploads", message.file_name);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    res.json({
      success: true,
      message: "Message deleted successfully",
      id,
    });
  } catch (err) {
    console.error("DELETE MESSAGE ERROR:", err);
    res.status(500).json({ message: "Delete message error" });
  }
});

module.exports = router;