// server.js - Fixed Prayer Tracker Server
require('dotenv').config();
const cron = require('node-cron');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const cors = require('cors');

const db = require('./db'); // sqlite3 Database instance
const getLocation = require('./getLocation'); // returns { latitude, longitude, city, country }
const { PrayerTimes, CalculationMethod, Coordinates } = require('adhan');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-session-secret';

// Validation for required environment variables
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.error('Missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET');
    process.exit(1);
}

// --- Promisified sqlite helpers ---
const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});

const dbAllP = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});

const dbRunP = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve({ lastID: this.lastID, changes: this.changes });
    });
});

// --- Middleware ---
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));
app.use(passport.initialize());
app.use(passport.session());

// Serve static frontend from /public
app.use(express.static(path.join(__dirname, 'public')));

// Request logger
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} -> ${req.method} ${req.url}`);
    next();
});

// --- Utility Functions ---
/**
 * Formats a Date object into HH:MM:SS string, ignoring server timezone.
 * This correctly preserves the time calculated by the adhan library.
 * @param {Date} d The date object to format.
 * @returns {string|null} The formatted time string or null.
 */
function fmtTime(d) {
    if (!d) return null;
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

function getLocalDateYMD(d = new Date()) {
    return d.toLocaleDateString('en-CA'); // YYYY-MM-DD format
}

function normalizeDateString(s) {
    if (!s) return null;
    return String(s).slice(0, 10);
}

function to12Hour(timeStr) {
    if (!timeStr) return null;
    const [h, m] = timeStr.split(':').map(Number);
    const ampm = h >= 12 ? 'PM' : 'AM';
    const hour12 = (h % 12) || 12;
    return `${hour12}:${m.toString().padStart(2, '0')} ${ampm}`;
}

const ALLOWED_PRAYERS = ['fajr', 'shurooq', 'dhuhr', 'asr', 'maghrib', 'isha'];

// --- Database Setup ---
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             username TEXT UNIQUE,
                                             password TEXT,
                                             name TEXT,
                                             google_id TEXT UNIQUE,
                                             created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Prayer times table
    db.run(`
        CREATE TABLE IF NOT EXISTS prayer_times (
                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    user_id INTEGER NOT NULL,
                                                    date TEXT NOT NULL,
                                                    fajr TEXT,
                                                    shurooq TEXT,
                                                    dhuhr TEXT,
                                                    asr TEXT,
                                                    maghrib TEXT,
                                                    isha TEXT,
                                                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                    FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, date)
            )
    `);

    // Prayer status table
    db.run(`
        CREATE TABLE IF NOT EXISTS prayer_status (
                                                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                     user_id INTEGER NOT NULL,
                                                     date TEXT NOT NULL,
                                                     prayer_name TEXT NOT NULL,
                                                     done INTEGER DEFAULT 0,
                                                     done_at TEXT DEFAULT NULL,
                                                     status TEXT DEFAULT 'pending',
                                                     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                     FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, date, prayer_name)
            )
    `);

    // Prayer log table
    db.run(`
        CREATE TABLE IF NOT EXISTS prayer_log (
                                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                  user_id INTEGER,
                                                  prayer_name TEXT,
                                                  action TEXT,
                                                  status TEXT,
                                                  timestamp TEXT,
                                                  FOREIGN KEY (user_id) REFERENCES users(id)
            )
    `);

    // Groups table
    db.run(`
        CREATE TABLE IF NOT EXISTS groups (
                                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                                              name TEXT NOT NULL,
                                              owner_id INTEGER NOT NULL,
                                              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                              FOREIGN KEY (owner_id) REFERENCES users(id)
            )
    `);

    // Group members table
    db.run(`
        CREATE TABLE IF NOT EXISTS group_members (
                                                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                     group_id INTEGER NOT NULL,
                                                     user_id INTEGER NOT NULL,
                                                     joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                     FOREIGN KEY (group_id) REFERENCES groups(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(group_id, user_id)
            )
    `);

    // Create indexes
    db.run(`CREATE INDEX IF NOT EXISTS idx_prayer_times_user_date ON prayer_times(user_id, date)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_prayer_status_user_date ON prayer_status(user_id, date)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_prayer_log_user_timestamp ON prayer_log(user_id, timestamp)`);

    // Check and add missing columns
    dbAllP("PRAGMA table_info(prayer_status)")
        .then(cols => {
            if (!cols.some(c => c.name === 'status')) {
                console.log('Adding status column to prayer_status');
                return dbRunP("ALTER TABLE prayer_status ADD COLUMN status TEXT DEFAULT 'pending'");
            }
        })
        .catch(e => console.warn('Schema check prayer_status failed:', e.message));

    dbAllP("PRAGMA table_info(prayer_log)")
        .then(cols => {
            if (!cols.some(c => c.name === 'status')) {
                console.log('Adding status column to prayer_log');
                return dbRunP("ALTER TABLE prayer_log ADD COLUMN status TEXT");
            }
        })
        .catch(e => console.warn('Schema check prayer_log failed:', e.message));

    // --- Ensure group_members has role column (owner/member) ---
    dbAllP("PRAGMA table_info(group_members)")
        .then(cols => {
            if (!cols.some(c => c.name === 'role')) {
                console.log('Adding role column to group_members');
                return dbRunP("ALTER TABLE group_members ADD COLUMN role TEXT DEFAULT 'member'");
            }
        })
        .catch(e => console.warn('Schema check group_members failed:', e.message));

});

// --- Passport Configuration ---
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production'
        ? `${process.env.BASE_URL}/auth/google/callback`
        : `http://localhost:${PORT}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await dbGet('SELECT * FROM users WHERE google_id = ?', [profile.id]);

        if (user) {
            return done(null, user);
        }

        // Create new user
        const result = await dbRunP(
            'INSERT INTO users (name, google_id) VALUES (?, ?)',
            [profile.displayName, profile.id]
        );

        user = await dbGet('SELECT * FROM users WHERE id = ?', [result.lastID]);
        return done(null, user);
    } catch (err) {
        console.error('Google OAuth error:', err);
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// --- Helper Functions ---
function ensurePrayerStatusRows(userId, date) {
    return new Promise((resolve, reject) => {
        const prayers = ALLOWED_PRAYERS;
        let completed = 0;
        let hasError = false;

        prayers.forEach(prayer => {
            db.run(
                'INSERT OR IGNORE INTO prayer_status (user_id, date, prayer_name, done) VALUES (?, ?, ?, 0)',
                [userId, date, prayer],
                (err) => {
                    if (err && !hasError) {
                        hasError = true;
                        return reject(err);
                    }
                    completed++;
                    if (completed === prayers.length && !hasError) {
                        resolve();
                    }
                }
            );
        });
    });
}

function calculatePrayerTimesForDate(lat, lon, forDate = new Date(), method = CalculationMethod.Egyptian()) {
    try {
        const coords = new Coordinates(Number(lat), Number(lon));
        const params = method;
        const pt = new PrayerTimes(coords, forDate, params);

        return {
            fajr: fmtTime(pt.fajr),
            shurooq: fmtTime(pt.sunrise),
            dhuhr: fmtTime(pt.dhuhr),
            asr: fmtTime(pt.asr),
            maghrib: fmtTime(pt.maghrib),
            isha: fmtTime(pt.isha)
        };
    } catch (err) {
        console.error('Error calculating prayer times:', err);
        throw new Error('Failed to calculate prayer times');
    }
}

// --- Routes ---

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'frontend.html'));
});

// Get current user info
app.get('/api/me', (req, res) => {
    if (req.user) {
        const { id, name, username, google_id } = req.user;
        return res.json({ loggedIn: true, id, name, username, google_id });
    }
    res.json({ loggedIn: false });
});

// Create user (basic username/password)
app.post('/users', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        const result = await dbRunP(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, password]
        );

        res.status(201).json({ id: result.lastID, username });
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT' || (err.message && err.message.includes('UNIQUE'))) {
            return res.status(409).json({ error: 'Username already exists.' });
        }
        console.error('Create user error:', err);
        res.status(500).json({ error: 'Failed to create user.' });
    }
});

// Get prayer times (live calculation)
app.get('/prayer-times', async (req, res) => {
    try {
        const location = await getLocation();

        if (!location || typeof location.latitude !== 'number' || typeof location.longitude !== 'number') {
            return res.status(500).json({ error: 'Invalid location data.' });
        }

        const today = new Date();
        const times = calculatePrayerTimesForDate(location.latitude, location.longitude, today);

        res.json({
            city: location.city,
            country: location.country,
            ...times
        });
    } catch (err) {
        console.error('GET /prayer-times error:', err);
        res.status(500).json({ error: 'Failed to calculate prayer times.' });
    }
});

// Save prayer times
app.post('/prayer-times/save', async (req, res) => {
    try {
        const userId = req.query.userId || req.body.userId;
        let lat = req.query.lat || req.body.lat;
        let lon = req.query.lon || req.body.lon;

        if (!userId) {
            return res.status(400).json({ error: 'userId is required' });
        }

        // Get location if not provided
        if (!lat || !lon) {
            try {
                const location = await getLocation();
                if (location && typeof location.latitude === 'number' && typeof location.longitude === 'number') {
                    lat = location.latitude;
                    lon = location.longitude;
                }
            } catch (locErr) {
                console.warn('getLocation failed:', locErr.message);
            }
        }

        if (!lat || !lon) {
            return res.status(400).json({
                error: 'Location coordinates missing. Please provide lat/lon or enable location services.'
            });
        }

        const todayDate = getLocalDateYMD();
        const today = new Date();
        const times = calculatePrayerTimesForDate(lat, lon, today);

        console.log(`Saving prayer times for userId=${userId}, date=${todayDate}, lat=${lat}, lon=${lon}`);

        await dbRunP(
            `INSERT INTO prayer_times (user_id, date, fajr, shurooq, dhuhr, asr, maghrib, isha)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(user_id, date) DO UPDATE SET
               fajr=excluded.fajr, shurooq=excluded.shurooq, dhuhr=excluded.dhuhr,
               asr=excluded.asr, maghrib=excluded.maghrib, isha=excluded.isha`,
            [userId, todayDate, times.fajr, times.shurooq, times.dhuhr, times.asr, times.maghrib, times.isha]
        );

        // Ensure checklist rows exist
        await ensurePrayerStatusRows(userId, todayDate);

        res.status(201).json({
            times,
            message: 'Prayer times saved and checklist initialized.',
            date: todayDate
        });
    } catch (error) {
        console.error('POST /prayer-times/save error:', error);
        res.status(500).json({ error: 'Failed to save prayer times' });
    }
});

// Get saved prayer times
app.get('/prayer-times/:userId/:date', async (req, res) => {
    try {
        const userId = Number(req.params.userId);
        const date = normalizeDateString(req.params.date);

        if (!userId || !date) {
            return res.status(400).json({ error: 'Invalid userId or date' });
        }

        const row = await dbGet('SELECT * FROM prayer_times WHERE user_id = ? AND date = ?', [userId, date]);

        if (!row) {
            return res.status(404).json({ error: 'No saved prayer times for that user/date.' });
        }

        const { fajr, shurooq, dhuhr, asr, maghrib, isha } = row;
        res.json({ userId, date, fajr, shurooq, dhuhr, asr, maghrib, isha });
    } catch (err) {
        console.error('GET prayer times error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get today's checklist
app.get('/prayers/today/:userId', async (req, res) => {
    try {
        const userId = Number(req.params.userId);

        if (!userId) {
            return res.status(400).json({ error: 'Invalid userId' });
        }

        const date = (req.query.date && normalizeDateString(req.query.date)) || getLocalDateYMD();

        const query = `
            SELECT prayer_name, done, status, done_at FROM prayer_status
            WHERE user_id = ? AND date = ?
            ORDER BY CASE prayer_name
                WHEN 'fajr' THEN 1 WHEN 'shurooq' THEN 2 WHEN 'dhuhr' THEN 3
                WHEN 'asr' THEN 4 WHEN 'maghrib' THEN 5 WHEN 'isha' THEN 6 ELSE 7 END
        `;

        let rows = await dbAllP(query, [userId, date]);

        if (!rows || rows.length === 0) {
            await ensurePrayerStatusRows(userId, date);
            rows = await dbAllP(query, [userId, date]);
        }

        res.json({ date, userId, checklist: rows });
    } catch (err) {
        console.error('GET prayers/today error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Mark prayer as done
app.post('/prayers/mark', async (req, res) => {
    try {
        const userId = Number(req.body.userId);
        const prayerName = (req.body.prayerName || '').toLowerCase();
        const date = req.body.date ? normalizeDateString(req.body.date) : null;

        if (!userId || !prayerName || !date) {
            return res.status(400).json({ error: 'userId, prayerName, and date are required.' });
        }

        if (!ALLOWED_PRAYERS.includes(prayerName)) {
            return res.status(400).json({
                error: `prayerName must be one of: ${ALLOWED_PRAYERS.join(', ')}`
            });
        }

        const timesRow = await dbGet('SELECT * FROM prayer_times WHERE user_id = ? AND date = ?', [userId, date]);

        if (!timesRow) {
            return res.status(400).json({
                error: 'No prayer times for today. Please save prayer times first.'
            });
        }

        const scheduledStr = timesRow[prayerName];
        if (!scheduledStr) {
            return res.status(500).json({ error: `Scheduled time missing for ${prayerName}` });
        }

        const scheduled = new Date(`${date}T${scheduledStr}`);
        const now = new Date();

        if (isNaN(scheduled.getTime())) {
            return res.status(500).json({ error: `Invalid scheduled time: ${scheduledStr}` });
        }

        if (now < scheduled) {
            return res.status(403).json({
                error: `You cannot mark ${prayerName} before its time (${to12Hour(scheduledStr)})`
            });
        }

        // --- FIX: Correct "late" status logic ---
        let status = 'on_time'; // Default to on_time
        const prayerSequenceForMarking = ['fajr', 'dhuhr', 'asr', 'maghrib', 'isha'];
        const currentPrayerIndex = prayerSequenceForMarking.indexOf(prayerName);

        let endTimePrayerName = null;
        if (prayerName === 'fajr') {
            endTimePrayerName = 'shurooq'; // Fajr ends at Shurooq
        } else if (currentPrayerIndex > -1 && currentPrayerIndex < prayerSequenceForMarking.length - 1) {
            // For Dhuhr, Asr, Maghrib, the end time is the start of the next prayer
            endTimePrayerName = prayerSequenceForMarking[currentPrayerIndex + 1];
        }
        // For Isha, there's no defined end time in the list, so it will always be 'on_time'

        if (endTimePrayerName) {
            const endTimeStr = timesRow[endTimePrayerName];
            if (endTimeStr) {
                const endTime = new Date(`${date}T${endTimeStr}`);
                if (now > endTime) {
                    status = 'late';
                }
            }
        }
        // --- End of fix ---

        const doneTimestamp = new Date().toISOString();

        const updateRes = await dbRunP(
            `UPDATE prayer_status
             SET done = 1, done_at = ?, status = ?
             WHERE user_id = ? AND date = ? AND prayer_name = ? AND done = 0`,
            [doneTimestamp, status, userId, date, prayerName]
        );

        if (updateRes.changes === 1) {
            await dbRunP(
                `INSERT INTO prayer_log (user_id, prayer_name, action, status, timestamp)
                 VALUES (?, ?, 'marked', ?, ?)`,
                [userId, prayerName, status, doneTimestamp]
            );

            return res.json({
                message: `Prayer marked as ${status}.`,
                prayerName,
                status,
                date
            });
        }

        return res.status(409).json({ error: 'Prayer already marked for this date.' });
    } catch (err) {
        console.error('POST /prayers/mark error:', err);
        res.status(500).json({ error: err.message || 'Failed to mark prayer' });
    }
});

// Prayer History API
app.get('/api/history/:userId', async (req, res) => {
    try {
        const userId = Number(req.params.userId);
        if (!userId) {
            return res.status(400).json({ error: "Invalid userId" });
        }

        const { start, end } = req.query;
        let sql = `SELECT * FROM prayer_log WHERE user_id = ?`;
        const params = [userId];

        if (start && end) {
            sql += ` AND date(timestamp) BETWEEN date(?) AND date(?)`;
            params.push(start, end);
        } else {
            sql += ` AND date(timestamp) >= date('now', '-7 days')`;
        }

        sql += ` ORDER BY timestamp DESC`;

        const rows = await dbAllP(sql, params);
        res.json({ userId, history: rows });
    } catch (err) {
        console.error('GET history error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Group API
app.post('/api/groups', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: "Not authenticated" });
        }

        const { name } = req.body;
        if (!name) {
            return res.status(400).json({ error: "Group name is required" });
        }

        const ownerId = req.user.id;
        const result = await dbRunP('INSERT INTO groups (name, owner_id) VALUES (?, ?)', [name, ownerId]);
        await dbRunP('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [result.lastID, ownerId]);

        res.status(201).json({ id: result.lastID, name });
    } catch (err) {
        console.error('POST groups error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: "Not authenticated" });
        }

        const groups = await dbAllP(
            'SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?',
            [req.user.id]
        );

        res.json(groups);
    } catch (err) {
        console.error('GET groups error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups/:groupId', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: "Not authenticated" });
        }

        const groupId = Number(req.params.groupId);
        if (!groupId) {
            return res.status(400).json({ error: "Invalid groupId" });
        }

        // Check membership
        const memberCheck = await dbGet(
            'SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
            [groupId, req.user.id]
        );

        if (!memberCheck) {
            return res.status(403).json({ error: "You are not a member of this group." });
        }

        const members = await dbAllP(
            'SELECT u.id, u.name FROM users u JOIN group_members gm ON u.id = gm.user_id WHERE gm.group_id = ?',
            [groupId]
        );

        const prayerStatus = await dbAllP(
            `SELECT ps.*, u.name as userName
             FROM prayer_status ps
             JOIN group_members gm ON ps.user_id = gm.user_id
             JOIN users u ON ps.user_id = u.id
             WHERE gm.group_id = ? AND ps.date = ?
             ORDER BY ps.user_id`,
            [groupId, getLocalDateYMD()]
        );

        res.json({ members, prayerStatus });
    } catch (err) {
        console.error('GET group details error:', err);
        res.status(500).json({ error: err.message });
    }
});
// === Invite user to a group ===
app.post('/api/groups/:groupId/invite', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: "Not authenticated" });
        }

        const groupId = Number(req.params.groupId);
        const { userId } = req.body; // the user to invite

        if (!groupId || !userId) {
            return res.status(400).json({ error: "groupId and userId are required" });
        }

        // Check that the current user is the group owner
        const group = await dbGet(
            'SELECT * FROM groups WHERE id = ? AND owner_id = ?',
            [groupId, req.user.id]
        );
        if (!group) {
            return res.status(403).json({ error: "Only the group owner can invite." });
        }

        // Check if already a member
        const exists = await dbGet(
            'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
            [groupId, userId]
        );
        if (exists) {
            return res.status(400).json({ error: "User is already a member." });
        }

        // Insert new member
        await dbRunP(
            'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
            [groupId, userId]
        );

        res.status(201).json({ success: true });
    } catch (err) {
        console.error('POST group invite error:', err);
        res.status(500).json({ error: err.message });
    }
});


// --- Authentication Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// --- Cron Jobs ---
// Nightly job to auto-mark missed prayers
cron.schedule('5 0 * * *', async () => {
    try {
        const yesterday = getLocalDateYMD(new Date(Date.now() - 86400000));
        console.log(`🕰️ Nightly check: finalizing prayers for ${yesterday}`);

        const rows = await dbAllP(`SELECT * FROM prayer_status WHERE date=? AND done=0`, [yesterday]);

        for (const row of rows) {
            await dbRunP(
                `UPDATE prayer_status SET status='not_done' WHERE id=?`,
                [row.id]
            );

            await dbRunP(
                `INSERT INTO prayer_log (user_id, prayer_name, action, status, timestamp)
                 VALUES (?, ?, 'auto_mark', 'not_done', ?)`,
                [row.user_id, row.prayer_name, new Date().toISOString()]
            );
        }

        console.log(`✅ Processed ${rows.length} missed prayers for ${yesterday}`);
    } catch (err) {
        console.error('Nightly job error:', err);
    }
});

// --- Error Handling ---
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ------------------ GROUPS FEATURE ------------------

// Create a new group
app.post("/groups", (req, res) => {
    const { name, owner_id } = req.body;
    if (!name || !owner_id) {
        return res.status(400).json({ error: "Group name and owner_id required" });
    }

    db.run(
        "INSERT INTO groups (name, owner_id, created_at) VALUES (?, ?, datetime('now'))",
        [name, owner_id],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ group_id: this.lastID, name, owner_id });
        }
    );
});

// Invite a user to a group (owner only)
app.post("/groups/:id/invite", (req, res) => {
    const group_id = req.params.id;
    const { owner_id, user_id } = req.body;

    if (!owner_id || !user_id) {
        return res.status(400).json({ error: "owner_id and user_id required" });
    }

    // check ownership
    db.get("SELECT * FROM groups WHERE id = ? AND owner_id = ?", [group_id, owner_id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(403).json({ error: "Only group owner can invite" });

        db.run(
            "INSERT INTO group_members (group_id, user_id, role, joined_at) VALUES (?, ?, 'member', datetime('now'))",
            [group_id, user_id],
            function (err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json({ success: true, group_id, user_id });
            }
        );
    });
});

// Get group members
app.get("/groups/:id/members", (req, res) => {
    const group_id = req.params.id;

    db.all(
        "SELECT user_id, role, joined_at FROM group_members WHERE group_id = ?",
        [group_id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ group_id, members: rows });
        }
    );
});

// Get prayers for all group members
app.get("/groups/:id/prayers", (req, res) => {
    const group_id = req.params.id;

    const query = `
        SELECT gm.user_id, p.date, p.fajr, p.dhuhr, p.asr, p.maghrib, p.isha, p.shurooq
        FROM group_members gm
        LEFT JOIN prayers p ON gm.user_id = p.user_id
        WHERE gm.group_id = ?
    `;

    db.all(query, [group_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ group_id, prayers: rows });
    });
});

// ---------------- END GROUPS FEATURE ----------------


// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});


// --- Start Server ---
const server = app.listen(PORT, () => {
    console.log(`🚀 Prayer Tracker Server running at http://localhost:${PORT}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} already in use.`);
        process.exit(1);
    } else {
        console.error('❌ Server error:', err);
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🔄 Shutting down server...');
    server.close(() => {
        console.log('✅ Server closed.');
        db.close();
        process.exit(0);
    });
});

module.exports = app;