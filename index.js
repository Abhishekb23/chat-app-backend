require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");

const { pool } = require("./config/db");

const authRoutes = require("./routes/authRoutes");
const conversationRoutes = require("./routes/conversationRoutes");
const userRoutes = require("./routes/userRoutes");
const messageRoutes = require("./routes/messageRoutes");
const groupRoutes = require("./routes/groupRoutes");

const initSocket = require("./socket/socket");

const app = express();
const server = http.createServer(app);

// Allow all origins
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Socket.IO allow all origins
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  },
});

app.set("io", io);

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/conversations", conversationRoutes);
app.use("/api", messageRoutes);
app.use("/api/groups", groupRoutes);

initSocket(io);

const PORT = process.env.PORT || 5000;

(async () => {
  try {
    const client = await pool.connect();
    client.release();
    console.log("PostgreSQL connected");

    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on ${PORT}`);
      console.log("CORS: All origins allowed");
    });
  } catch (err) {
    console.error("Database connection error:", err);
  }
})();