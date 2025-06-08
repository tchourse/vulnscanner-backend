const express = require("express");
const router = express.Router();  // ✅ Initialize router
const pool = require("../db");  
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Sign Up Route
router.post("/signup", async (req, res) => {
  const { name, institute, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      const user = existingUser.rows[0];
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '24h' }
      );
      return res.json({
        success: true,
        message: "User already exists. Please sign in.",
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          institute: user.institute
        },
        token
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, institute, email, password) VALUES ($1, $2, $3, $4)",
      [name, institute, email, hashedPassword]
    );
    
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      success: true,
      message: 'Signup successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        institute: user.institute
      },
      token
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Sign In Route
router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) {
      return res.json({ success: false, message: "Invalid credentials" });
    }
    
    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid credentials" });
    }
    
    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ success: true, message: "Logged in successfully", token });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;  // ✅ Export router at the end
