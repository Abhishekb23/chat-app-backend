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

const allowedOrigins = [
  "http://localhost:3000",
  "https://chat-app-frontend-jet-five.vercel.app",
];

if (process.env.CLIENT_URL && !allowedOrigins.includes(process.env.CLIENT_URL)) {
  allowedOrigins.push(process.env.CLIENT_URL);
}

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(helmet({
  crossOriginResourcePolicy: false,
}));

app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true,
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
    await pool.connect();
    console.log("PostgreSQL connected");

    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on ${PORT}`);
      console.log("Allowed origins:", allowedOrigins);
    });
  } catch (err) {
    console.error(err);
  }
})();