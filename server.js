const express = require("express");
const cors = require("cors");
const http = require("http");
const socketio = require("socket.io");
const path = require("path");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const server = http.createServer(app);

// Allow CORS for dashboard app
app.use(cors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:3000", "http://127.0.0.1:3000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "static")));

// PostgreSQL
const { pool, query } = require("./db");

// Mock users for demo purposes
const mockUsers = [
  {
    id: 1,
    name: "Test User",
    email: "test@example.com",
    password: "$2a$10$X7.H4QUv3gZIQPiYRCGwLeYxCNQ/xAzTLuq7v5XsVLNpDdpMR9IgG", // "password"
    institute: "Test Institute"
  }
];

// Modified query function to handle database failures
async function safeQuery(text, params) {
  try {
    const res = await query(text, params);
    return { success: true, rows: res.rows, rowCount: res.rowCount };
  } catch (error) {
    console.error("Database error:", error.message);
    return { success: false, error: error.message };
  }
}

// Serve the socket.io client library
app.use("/socket.io", express.static(path.join(__dirname, "node_modules", "socket.io", "client-dist")));

const io = socketio(server, {
  cors: {
    origin: ["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Track user activity and scans
const connectedUsers = new Set();
let scanRequestCount = 0;
let liveVulnerabilities = [];

io.on("connection", (socket) => {
  console.log("🔌 WebSocket connected:", socket.id);

  socket.on("user_connected", (email) => {
    if (email) {
      connectedUsers.add(email);
      socket.email = email;
      console.log(`✅ User connected: ${email}`);
    }
    emitDashboardStats();
  });

  socket.on("scan_started", (payload) => {
    scanRequestCount++;
    emitDashboardStats();

    const newVulns = generateMockVulnerabilities(payload.url);
    liveVulnerabilities.push(...newVulns);

    io.emit("new_vulnerabilities", newVulns);
  });

  socket.on("user_browsing", (data) => {
    console.log("🌐 Browsing data received:", data);
  });

  socket.on("disconnect", () => {
    if (socket.email) {
      connectedUsers.delete(socket.email);
      console.log(`❌ User disconnected: ${socket.email}`);
      emitDashboardStats();
    }
  });
});

function emitDashboardStats() {
  io.emit("dashboard_stats", {
    totalScans: 120,
    scanRequests: scanRequestCount,
    activeUsers: Array.from(connectedUsers),
  });
}

function generateMockVulnerabilities(targetUrl) {
  const timestamp = new Date().toISOString();
  
  // Base vulnerabilities that appear for all scans
  const baseVulnerabilities = [
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Security Headers",
      severity: "Medium",
      description: "Missing X-Frame-Options header (clickjacking protection)",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Security Headers",
      severity: "Medium",
      description: "Missing X-Content-Type-Options header (MIME-sniffing protection)",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Security Headers",
      severity: "Medium",
      description: "Missing HSTS header (HTTPS enforcement)",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "HSTS",
      severity: "Medium",
      description: "HSTS header not implemented. This may allow downgrade attacks.",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    }
  ];
  
  // Additional vulnerabilities that may appear randomly
  const additionalVulnerabilities = [
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "XSS",
      severity: "High",
      description: "Reflected XSS vulnerability in search parameter",
      location: `${targetUrl}/search?q=`,
      payload: "<script>alert(1)</script>",
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "SQL Injection",
      severity: "High",
      description: "Possible SQL injection in user parameter",
      location: `${targetUrl}/user?id=`,
      payload: "1' OR '1'='1",
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "CSRF",
      severity: "High",
      description: "Form without CSRF protection detected",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Information Disclosure",
      severity: "Low",
      description: "Server software disclosed: nginx",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Information Disclosure",
      severity: "Medium",
      description: "Software version disclosure in meta tag: WordPress 6.2.6",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Insecure Cookies",
      severity: "Medium",
      description: "Cookie without Secure flag set",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "SPF",
      severity: "Medium",
      description: "SPF record not implemented",
      location: targetUrl.replace(/^https?:\/\//, ''),
      payload: null,
      detectedAt: timestamp
    },
    {
      id: Math.random().toString(36).substr(2, 9),
      type: "Server Version",
      severity: "Medium",
      description: "Server running outdated Apache version 2.4.29",
      location: targetUrl,
      payload: null,
      detectedAt: timestamp
    }
  ];
  
  // Randomly select 2-6 additional vulnerabilities
  const numAdditionalVulns = Math.floor(Math.random() * 5) + 2;
  const selectedAdditionalVulns = [];
  
  for (let i = 0; i < numAdditionalVulns; i++) {
    const randomIndex = Math.floor(Math.random() * additionalVulnerabilities.length);
    selectedAdditionalVulns.push(additionalVulnerabilities[randomIndex]);
    // Remove the selected vulnerability to avoid duplicates
    additionalVulnerabilities.splice(randomIndex, 1);
    
    if (additionalVulnerabilities.length === 0) break;
  }
  
  return [...baseVulnerabilities, ...selectedAdditionalVulns];
}

// ------------------ API Routes ------------------

app.post("/api/signup", async (req, res) => {
  const { name, institute, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    const exists = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (exists.rows.length > 0) {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await query(
      "INSERT INTO users (name, institute, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, institute, email, hashedPassword]
    );

    return res.status(201).json({
      success: true,
      message: "Signup successful",
      user: { id: result.rows[0].id, name, email, institute }
    });
  } catch (error) {
    console.error("Signup Error:", error.message);
    return res.status(500).json({ success: false, message: "Signup failed" });
  }
});

app.post("/api/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }

  try {
    // Try database first
    const result = await safeQuery("SELECT * FROM users WHERE email = $1", [email]);

    // If database query failed or returned no results, try mock users
    if (!result.success || result.rows.length === 0) {
      console.log("Using mock users for authentication");
      
      const mockUser = mockUsers.find(u => u.email === email);
      
      if (!mockUser) {
        return res.status(401).json({ success: false, message: "Invalid email or password" });
      }

      const match = await bcrypt.compare(password, mockUser.password);
      
      if (!match) {
        return res.status(401).json({ success: false, message: "Invalid email or password" });
      }

      return res.status(200).json({
        success: true,
        message: "Login successful (DEMO MODE)",
        user: { 
          id: mockUser.id, 
          name: mockUser.name, 
          email: mockUser.email, 
          institute: mockUser.institute 
        }
      });
    }

    // Regular database authentication
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    return res.status(200).json({
      success: true,
      message: "Login successful",
      user: { id: user.id, name: user.name, email: user.email, institute: user.institute }
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    return res.status(500).json({ success: false, message: "Login failed" });
  }
});

// Add a route handler for GET requests to /api/signin
app.get("/api/signin", (req, res) => {
  res.status(405).json({ success: false, message: "Method not allowed. Use POST for signin." });
});

app.post("/api/start-scan", (req, res) => {
  const targeturl = req.body.targeturl || req.body.targetUrl || req.body.url;

  if (!targeturl) {
    return res.status(400).json({ error: "Missing target URL", success: false });
  }

  console.log(`📡 Scan started for: ${targeturl}`);
  scanRequestCount++;
  emitDashboardStats();

  // Generate mock vulnerabilities 
  const newVulns = generateMockVulnerabilities(targeturl);
  liveVulnerabilities.push(...newVulns);

  // Emit scan results via Socket.IO
  io.emit("scan_results", {
    scanId: Date.now(),
    status: "completed",
    results: {
      vulnerabilities: newVulns,
      target: targeturl
    }
  });

  return res.status(200).json({
    success: true,
    message: "Scan started successfully",
    scanId: Date.now(),
    target: targeturl,
    status: "Scanning in progress..."
  });
});

app.get("/api/vulnerabilities", (req, res) => {
  res.json({ success: true, vulnerabilities: liveVulnerabilities });
});

app.get("/api/charts", (req, res) => {
  // Count vulnerability types and severities
  const vulnerabilityTypes = {};
  const severityDistribution = { High: 0, Medium: 0, Low: 0 };
  const trends = {};
  
  // Process real vulnerabilities from liveVulnerabilities
  liveVulnerabilities.forEach(vuln => {
    // Count by type
    vulnerabilityTypes[vuln.type] = (vulnerabilityTypes[vuln.type] || 0) + 1;
    
    // Count by severity
    if (vuln.severity) {
      severityDistribution[vuln.severity] = (severityDistribution[vuln.severity] || 0) + 1;
    }
    
    // Add to trends
    if (vuln.detectedAt) {
      const date = new Date(vuln.detectedAt);
      const month = date.toLocaleString('default', { month: 'short', year: 'numeric' });
      
      if (!trends[month]) {
        trends[month] = { High: 0, Medium: 0, Low: 0 };
      }
      
      if (vuln.severity) {
        trends[month][vuln.severity] = (trends[month][vuln.severity] || 0) + 1;
      }
    }
  });
  
  // For empty or nearly empty data, add some mock values
  if (Object.keys(vulnerabilityTypes).length < 3) {
    vulnerabilityTypes["SQL Injection"] = (vulnerabilityTypes["SQL Injection"] || 0) + 4;
    vulnerabilityTypes["XSS"] = (vulnerabilityTypes["XSS"] || 0) + 3;
    vulnerabilityTypes["CSRF"] = (vulnerabilityTypes["CSRF"] || 0) + 2;
    vulnerabilityTypes["Insecure Cookies"] = (vulnerabilityTypes["Insecure Cookies"] || 0) + 6;
    vulnerabilityTypes["HSTS"] = (vulnerabilityTypes["HSTS"] || 0) + 5;
    vulnerabilityTypes["SPF"] = (vulnerabilityTypes["SPF"] || 0) + 3;
  }
  
  // Ensure some data in severity distribution
  if (severityDistribution.High + severityDistribution.Medium + severityDistribution.Low < 5) {
    severityDistribution.High += 5;
    severityDistribution.Medium += 8;
    severityDistribution.Low += 12;
  }
  
  // Ensure we have some trend data
  const currentDate = new Date();
  for (let i = 2; i >= 0; i--) {
    const targetDate = new Date(currentDate);
    targetDate.setMonth(currentDate.getMonth() - i);
    const month = targetDate.toLocaleString('default', { month: 'short', year: 'numeric' });
    
    if (!trends[month]) {
      trends[month] = { 
        High: Math.floor(Math.random() * 5) + 1,
        Medium: Math.floor(Math.random() * 7) + 3,
        Low: Math.floor(Math.random() * 10) + 5
      };
    }
  }
  
  // Generate some risk score buckets
  const riskBuckets = {
    "Critical (90-100)": Math.floor(Math.random() * 3) + 1,
    "High (70-89)": Math.floor(Math.random() * 5) + 3,
    "Medium (40-69)": Math.floor(Math.random() * 8) + 5,
    "Low (10-39)": Math.floor(Math.random() * 10) + 8,
    "Info (1-9)": Math.floor(Math.random() * 12) + 10
  };
  
  // Generate scan activity
  const scanActivity = [];
  for (let i = 6; i >= 0; i--) {
    const activityDate = new Date();
    activityDate.setDate(activityDate.getDate() - i);
    
    scanActivity.push({
      date: activityDate.toISOString().split('T')[0],
      scans: Math.floor(Math.random() * 8) + 1
    });
  }
  
  const chartData = {
    vulnerabilityTypes,
    severityDistribution,
    scanActivity,
    trends,
    riskBuckets
  };

  res.json({ success: true, charts: chartData });
});

app.get('/api/scan_results', async (req, res) => {
  const { email } = req.query;

  try {
    const text = email
      ? 'SELECT * FROM scan_results WHERE email = $1 ORDER BY scan_time DESC'
      : 'SELECT * FROM scan_results ORDER BY scan_time DESC';

    const values = email ? [email] : [];

    const result = await pool.query(text, values);
    res.status(200).json({ success: true, results: result.rows });
  } catch (err) {
    console.error('Error fetching scan results:', err);
    res.status(500).json({ success: false, message: 'Error fetching scan results' });
  }
});

const PORT = 5500;
server.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  
  // Check if database tables exist
  try {
    const tableCheck = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'users'
      );
    `);
    
    const tablesExist = tableCheck.rows[0].exists;
    
    if (!tablesExist) {
      console.log("⚠️ Database tables don't exist. Please run: node init-db.js");
    } else {
      console.log("✅ Database tables verified");
      
      // Check for test user
      const testUser = await query("SELECT * FROM users WHERE email = $1", ["test@example.com"]);
      if (testUser.rows.length === 0) {
        console.log("ℹ️ No test user found. You can run init-db.js to create one.");
      } else {
        console.log("✅ Test user exists: test@example.com / password");
      }
    }
  } catch (error) {
    console.error("❌ Database check error:", error.message);
    console.log("⚠️ Please make sure PostgreSQL is running and init-db.js has been executed.");
  }
});
