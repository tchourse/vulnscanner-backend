const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
    user: process.env.DB_USER || "postgres",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "vulnerability_scanner",
    password: process.env.DB_PASS || "password",
    port: process.env.DB_PORT || 5432,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

const query = async (text, params) => {
    try {
        const res = await pool.query(text, params);
        return res;
    } catch (err) {
        console.error("❌ Database Query Error:", err.message);
        throw err;
    }
};

const checkConnection = async () => {
    try {
        const client = await pool.connect();
        console.log("✅ Database connected successfully!");
        client.release();
    } catch (err) {
        console.error("❌ Database connection failed:", err.message);
        process.exit(1);
    }
};

const gracefulShutdown = async () => {
    console.log("\n⚠️ Shutting down database connection...");
    await pool.end();
    console.log("✅ Database connection closed.");
    process.exit(0);
};

process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);

checkConnection();

module.exports = { pool, query };
