const { query } = require("../config/db");

const onlineUsers = new Map();

function initSocket(io) {
  io.on("connection", (socket) => {
    console.log("Socket connected:", socket.id);

    socket.on("register", (userId) => {
      const parsedUserId = Number(userId);
      if (!parsedUserId) return;

      onlineUsers.set(parsedUserId, socket.id);
      console.log(`User ${parsedUserId} registered with socket ${socket.id}`);
    });

    socket.on("join_conversation", (conversationId) => {
      const parsedConversationId = Number(conversationId);
      if (!parsedConversationId) return;

      const roomName = `conversation_${parsedConversationId}`;
      socket.join(roomName);
      console.log(`Socket ${socket.id} joined room ${roomName}`);
    });

    socket.on("leave_conversation", (conversationId) => {
      const parsedConversationId = Number(conversationId);
      if (!parsedConversationId) return;

      const roomName = `conversation_${parsedConversationId}`;
      socket.leave(roomName);
      console.log(`Socket ${socket.id} left room ${roomName}`);
    });

    socket.on("send_message", async (data) => {
      try {
        const conversationId = Number(data.conversationId);
        const senderId = Number(data.senderId);
        const content = String(data.content || "").trim();

        if (!conversationId || !senderId || !content) return;

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

        if (access.rows.length === 0) return;

        const result = await query(
          `
          INSERT INTO messages (conversation_id, sender_id, content, message_type)
          VALUES ($1::int, $2::int, $3, 'TEXT')
          RETURNING id
          `,
          [conversationId, senderId, content]
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
            NULL AS file_url,
            NULL AS original_name,
            NULL AS mime_type,
            NULL AS file_size
          FROM messages m
          JOIN users u ON u.id = m.sender_id
          WHERE m.id = $1::int
          `,
          [result.rows[0].id]
        );

        io.to(`conversation_${conversationId}`).emit(
          "receive_message",
          fullMessage.rows[0]
        );
      } catch (err) {
        console.error("SOCKET SEND MESSAGE ERROR:", err);
      }
    });

    socket.on("disconnect", () => {
      for (const [userId, id] of onlineUsers.entries()) {
        if (id === socket.id) {
          onlineUsers.delete(userId);
        }
      }
      console.log("Socket disconnected:", socket.id);
    });
  });
}

module.exports = initSocket;