const express = require("express");
const { query } = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

router.get("/search", auth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    const result = await query(
      `
      SELECT id, username
      FROM users
      WHERE id != $1
      AND username ILIKE $2
      ORDER BY username
      LIMIT 50
      `,
      [req.user.id, `%${q}%`]
    );

    res.json({
      success: true,
      users: result.rows,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "User search error" });
  }
});

module.exports = router;