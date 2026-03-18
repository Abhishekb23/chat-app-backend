const { query } = require("../config/db");

const onlineUsers = new Map();

function initSocket(io) {
  io.on("connection", (socket) => {
    socket.on("register", (userId) => {
      onlineUsers.set(Number(userId), socket.id);
    });

    socket.on("join_conversation", (conversationId) => {
      const roomName = `conversation_${Number(conversationId)}`;
      socket.join(roomName);
    });

    socket.on("leave_conversation", (conversationId) => {
      const roomName = `conversation_${Number(conversationId)}`;
      socket.leave(roomName);
    });

    socket.on("send_message", async (data) => {
      try {
        const conversationId = Number(data.conversationId);
        const senderId = Number(data.senderId);
        const content = String(data.content || "").trim();

        if (!conversationId || !senderId || !content) return;

        const result = await query(
          `
          INSERT INTO messages (conversation_id, sender_id, content)
          VALUES ($1::int, $2::int, $3)
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
            m.is_edited,
            m.is_deleted,
            m.created_at,
            m.updated_at
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
    });
  });
}

module.exports = initSocket;