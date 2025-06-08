const express = require('express');
const { exec } = require('child_process'); // To run Python script
const router = express.Router();

// Start scan in the background
router.post('/start-scan', (req, res) => {
    const targetURL = req.body.url; // Website to scan
    if (!targetURL) return res.status(400).json({ error: "URL is required" });

    // Run Python script in the background
    exec(`python3 scanner/scanner.py ${targetURL}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error starting scan: ${error.message}`);
            return res.status(500).json({ error: "Failed to start scan" });
        }
        res.json({ message: "Scan started in background", output: stdout });
    });
});

module.exports = router;
