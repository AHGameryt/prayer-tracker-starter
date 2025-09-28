// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

// RENDER DEPLOYMENT CHANGE:
// Check if we are in a production environment (Render sets NODE_ENV to 'production')
// If so, use the path for Render's persistent disk. Otherwise, use the local path.
const isProduction = process.env.NODE_ENV === "production";
const dataDir = isProduction ? "/var/data" : __dirname;

// Ensure the directory exists (important for the first run on Render)
if (isProduction) {
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }
}

const dbPath = path.join(dataDir, "prayers.db");
console.log(`[DB] Using database at: ${dbPath}`);

const db = new sqlite3.Database(dbPath);

// ---------- CREATE TABLES IF NOT EXISTS ----------
db.serialize(() => {
    // prayers table (assuming you already had this schema)
    db.run(`
        CREATE TABLE IF NOT EXISTS prayers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            fajr INTEGER DEFAULT 0,
            dhuhr INTEGER DEFAULT 0,
            asr INTEGER DEFAULT 0,
            maghrib INTEGER DEFAULT 0,
            isha INTEGER DEFAULT 0,
            shurooq INTEGER DEFAULT 0,
            UNIQUE(user_id, date)
        )
    `);

    // groups table
    db.run(`
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at TEXT
        )
    `);

    // group_members table
    db.run(`
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',
            joined_at TEXT,
            FOREIGN KEY (group_id) REFERENCES groups(id)
        )
    `);
});

module.exports = db;
