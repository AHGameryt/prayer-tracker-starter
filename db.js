// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require('fs');

// RENDER DEPLOYMENT CHANGE:
// Check if we are in a production environment (Render sets NODE_ENV to 'production')
// If so, use the path for Render's persistent disk. Otherwise, use the local path.
const isProduction = process.env.NODE_ENV === 'production';
const dataDir = isProduction ? '/var/data' : __dirname;

// Ensure the directory exists (important for the first run on Render)
if (isProduction) {
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }
}

const dbPath = path.join(dataDir, "prayers.db");
console.log(`[DB] Using database at: ${dbPath}`);

const db = new sqlite3.Database(dbPath);

module.exports = db;