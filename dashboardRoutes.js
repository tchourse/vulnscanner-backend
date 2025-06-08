const express = require("express");
const router = express.Router();
const db = require("../db");

// Fetch Stored Vulnerabilities from DB
router.get("/vulnerabilities", async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM vulnerabilities");
        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching vulnerabilities:", error);
        res.status(500).json({ message: "Error fetching vulnerabilities" });
    }
});

module.exports = router;
