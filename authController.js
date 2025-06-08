const bcrypt = require("bcrypt");
const pool = require("../db"); // PostgreSQL connection

// Signup Controller
exports.signup = async (req, res) => {
    try {
        const { name, institute, email, password } = req.body;

        // ✅ Check if the user already exists
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (userCheck.rows.length > 0) {
            return res.status(400).json({ message: "User already exists. Please sign in." });
        }

        // ✅ Hash the password before storing it
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // ✅ Insert user into the database
        await pool.query(
            "INSERT INTO users (name, institute, email, password) VALUES ($1, $2, $3, $4)",
            [name, institute, email, hashedPassword]
        );

        res.status(201).json({ message: "Signup successful! Redirecting to Sign In..." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error. Try again later." });
    }
};

// Signin Controller
exports.signin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // ✅ Check if the user exists
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (user.rows.length === 0) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        // ✅ Compare password hash
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        res.json({ message: "Login successful!", redirect: "index.html" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error. Try again later." });
    }
};
