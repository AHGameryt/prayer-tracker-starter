// server.rebuilt.fixed.js
// Cleaned and fixed server.js for Prayer Tracker
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
const SESSION_SECRET = process.env.SESSION_SECRET;
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

// --- Ensure schema columns exist (status columns) ---
db.serialize(() => {
    dbAllP("PRAGMA table_info(prayer_status)").then(cols => {
        if (!cols.some(c => c.name === 'status')) {
            console.log('Adding status column to prayer_status');
            return dbRunP("ALTER TABLE prayer_status ADD COLUMN status TEXT DEFAULT 'pending'");
        }
    }).catch(e => console.warn('Schema check prayer_status failed:', e.message));

    dbAllP("PRAGMA table_info(prayer_log)").then(cols => {
        if (!cols.some(c => c.name === 'status')) {
            console.log('Adding status column to prayer_log');
            return dbRunP("ALTER TABLE prayer_log ADD COLUMN status TEXT");
        }
    }).catch(e => console.warn('Schema check prayer_log failed:', e.message));
});

function to12Hour(timeStr) {
    if (!timeStr) return null;
    const [h, m] = timeStr.split(':').map(Number);
    const ampm = h >= 12 ? 'PM' : 'AM';
    const hour12 = (h % 12) || 12;
    return `${hour12}:${m.toString().padStart(2, '0')} ${ampm}`;
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// serve static frontend from /public
app.use(express.static(path.join(__dirname, 'public')));

// simple request logger
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} -> ${req.method} ${req.url}`);
    next();
});

// Helpers
function fmtTime(d) {
    if (!d) return null;
    return d.toTimeString().split(' ')[0]; // HH:MM:SS local
}

function getLocalDateYMD(d = new Date()) {
    return d.toLocaleDateString('en-CA');
}

function normalizeDateString(s) {
    if (!s) return null;
    return String(s).slice(0, 10);
}

const ALLOWED_PRAYERS = ['fajr', 'shurooq', 'dhuhr', 'asr', 'maghrib', 'isha'];

// Ensure tables and constraints
db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      name TEXT,
      google_id TEXT UNIQUE
    )
  `);

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
      UNIQUE(user_id, date)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS prayer_status (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      prayer_name TEXT NOT NULL,
      done INTEGER DEFAULT 0,
      done_at TEXT DEFAULT NULL,
      UNIQUE(user_id, date, prayer_name)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS prayer_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      prayer_name TEXT,
      action TEXT,
      timestamp TEXT
    )
  `);

    // New tables for group functionality
    db.run(`
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_id INTEGER NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS group_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      FOREIGN KEY (group_id) REFERENCES groups(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(group_id, user_id)
    )
  `);

    db.run(`CREATE INDEX IF NOT EXISTS idx_prayer_times_user_date ON prayer_times(user_id, date)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_prayer_status_user_date ON prayer_status(user_id, date)`);
});

// Passport Google strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:' + PORT + '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    db.get('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, row) => {
        if (err) return done(err);
        if (row) return done(null, row);

        db.run('INSERT INTO users (name, google_id) VALUES (?, ?)', [profile.displayName, profile.id], function (insertErr) {
            if (!insertErr) {
                db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (e, newRow) => {
                    if (e) return done(e);
                    return done(null, newRow);
                });
            } else {
                // fallback: try inserting username
                db.run('INSERT INTO users (username, google_id) VALUES (?, ?)', [profile.displayName, profile.id], function (insertErr2) {
                    if (!insertErr2) {
                        db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (e2, newRow2) => {
                            if (e2) return done(e2);
                            return done(null, newRow2);
                        });
                    } else {
                        console.error('Failed to insert Google user:', insertErr, insertErr2);
                        return done(null, { id: null, displayName: profile.displayName, google_id: profile.id });
                    }
                });
            }
        });
    });
}));

passport.serializeUser((user, done) => done(null, (user && user.id) ? user.id : user.google_id));
passport.deserializeUser((identifier, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [identifier], (err, row) => {
        if (err) return done(err);
        if (row) return done(null, row);
        db.get('SELECT * FROM users WHERE google_id = ?', [identifier], (err2, row2) => {
            if (err2) return done(err2);
            if (row2) return done(null, row2);
            done(null, { id: null, displayName: identifier });
        });
    });
});

// Return current logged-in user (for frontend)
app.get('/api/me', (req, res) => {
    if (req.user) {
        const { id, name, username, google_id } = req.user;
        return res.json({ loggedIn: true, id, name, username, google_id });
    }
    res.json({ loggedIn: false });
});

// Ensure prayer_status rows (one by one for reliability)
function ensurePrayerStatusRows(userId, date, cb) {
    const prayers = ALLOWED_PRAYERS;
    let i = 0;
    function next(err) {
        if (err) return cb(err);
        if (i >= prayers.length) return cb(null);
        const prayer = prayers[i++];
        db.run(
            'INSERT OR IGNORE INTO prayer_status (user_id, date, prayer_name, done) VALUES (?, ?, ?, 0)',
            [userId, date, prayer],
            (insertErr) => next(insertErr)
        );
    }
    next();
}

// Calculate prayer times using adhan
function calculatePrayerTimesForDate(lat, lon, forDate = new Date(), method = CalculationMethod.MuslimWorldLeague()) {
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
}

// Routes
// Serve frontend always for root — SPA will query /api/me to detect user
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'frontend.html'));
});

// Create user (basic username/password)
app.post('/users', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password are required.' });
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], function (err) {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT' || (err.message && err.message.includes('UNIQUE'))) {
                return res.status(409).json({ error: 'Username already exists.' });
            }
            return res.status(500).json({ error: 'Failed to add user.' });
        }
        res.status(201).json({ id: this.lastID, username });
    });
});

// GET prayer times (live calc using adhan & server getLocation())
app.get('/prayer-times', async (req, res) => {
    try {
        const location = await getLocation();
        if (!location || typeof location.latitude !== 'number' || typeof location.longitude !== 'number') {
            return res.status(500).json({ error: 'Invalid location data.' });
        }
        const today = new Date();
        const times = calculatePrayerTimesForDate(location.latitude, location.longitude, today);

        res.json({ city: location.city, country: location.country, ...times });
    } catch (err) {
        console.error('GET /prayer-times error:', err);
        res.status(500).json({ error: 'Failed to calculate prayer times.' });
    }
});

// Save prayer times for today (with checklist initialized)
// Accepts userId, lat, lon via query or body
app.post('/prayer-times/save', async (req, res) => {
    try {
        const userId = req.query.userId || req.body.userId;
        let lat = req.query.lat || req.body.lat;
        let lon = req.query.lon || req.body.lon;

        if (!userId) return res.status(400).json({ error: 'userId is required' });

        // If lat/lon not provided by client, try server-side getLocation()
        if (!lat || !lon) {
            try {
                const location = await getLocation();
                if (location && typeof location.latitude === 'number' && typeof location.longitude === 'number') {
                    lat = location.latitude;
                    lon = location.longitude;
                } else {
                    console.warn('server getLocation returned invalid:', location);
                }
            } catch (locErr) {
                console.warn('getLocation failed:', locErr && (locErr.message || locErr));
            }
        }

        const todayDate = getLocalDateYMD();
        const today = new Date();

        // If still missing lat/lon, return a helpful error
        if (!lat || !lon) {
            return res.status(400).json({ error: 'lat/lon missing — provide browser location or allow server to determine location.' });
        }

        // Log exactly which lat/lon will be used for calculating times
        console.log(`Using lat=${lat} lon=${lon} for userId=${userId} date=${todayDate}`);

        const times = calculatePrayerTimesForDate(lat, lon, today);

        // NOTE: ON CONFLICT(user_id, date) must match UNIQUE(user_id, date)
        db.run(
            `INSERT INTO prayer_times (user_id, date, fajr, shurooq, dhuhr, asr, maghrib, isha)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, date) DO UPDATE SET
         fajr=excluded.fajr, shurooq=excluded.shurooq, dhuhr=excluded.dhuhr,
         asr=excluded.asr, maghrib=excluded.maghrib, isha=excluded.isha`,
            [userId, todayDate, times.fajr, times.shurooq, times.dhuhr, times.asr, times.maghrib, times.isha],
            function (err) {
                if (err) {
                    console.error('DB error saving prayer_times:', err.message);
                    return res.status(500).json({ error: err.message });
                }

                // Ensure checklist rows exist for today
                ensurePrayerStatusRows(userId, todayDate, (ensureErr) => {
                    if (ensureErr) {
                        console.error('Failed to ensure prayer_status rows:', ensureErr.message);
                        return res.status(201).json({ times, message: 'Prayer times saved, but failed to initialize checklist.', ensured: false });
                    }
                    res.status(201).json({ times, message: 'Prayer times saved and checklist initialized.', ensured: true, date: todayDate });
                });
            }
        );
    } catch (error) {
        console.error('POST /prayer-times/save error:', error);
        res.status(500).json({ error: 'Failed to save prayer times' });
    }
});

// GET saved prayer times for a user/date
app.get('/prayer-times/:userId/:date', (req, res) => {
    const userId = Number(req.params.userId);
    const date = normalizeDateString(req.params.date);
    if (!userId || !date) return res.status(400).json({ error: 'Invalid userId or date' });

    db.get('SELECT * FROM prayer_times WHERE user_id = ? AND date = ?', [userId, date], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'No saved prayer times for that user/date.' });
        const { fajr, shurooq, dhuhr, asr, maghrib, isha } = row;
        res.json({ userId, date, fajr, shurooq, dhuhr, asr, maghrib, isha });
    });
});

// GET today's checklist for a user — uses local date or optional ?date=YYYY-MM-DD
app.get('/prayers/today/:userId', (req, res) => {
    const userId = Number(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'Invalid userId' });

    const date = (req.query.date && normalizeDateString(req.query.date)) || getLocalDateYMD();

    // THE FIX: Select the 'status' and 'done_at' columns as well.
    const query = `
        SELECT prayer_name, done, status, done_at FROM prayer_status
        WHERE user_id = ? AND date = ?
        ORDER BY CASE prayer_name
            WHEN 'fajr' THEN 1 WHEN 'shurooq' THEN 2 WHEN 'dhuhr' THEN 3
            WHEN 'asr' THEN 4 WHEN 'maghrib' THEN 5 WHEN 'isha' THEN 6 ELSE 7 END
    `;

    db.all(query, [userId, date], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!rows || rows.length === 0) {
            ensurePrayerStatusRows(userId, date, (ensureErr) => {
                if (ensureErr) return res.status(500).json({ error: ensureErr.message });
                db.all(query, [userId, date], (err2, newRows) => {
                    if (err2) return res.status(500).json({ error: err2.message });
                    res.json({ date, userId, checklist: newRows });
                });
            });
        } else {
            res.json({ date, userId, checklist: rows });
        }
    });
});

// Mark a prayer as done (time-validated — no early marking; late if next prayer has started)
app.post('/prayers/mark', async (req, res) => {
    try {
        const userId = Number(req.body.userId || req.query.userId);
        const prayerName = (req.body.prayerName || req.query.prayerName || '').toLowerCase();
        const date = (req.body.date && normalizeDateString(req.body.date)) || getLocalDateYMD();

        if (!userId || !prayerName) return res.status(400).json({ error: 'Both userId and prayerName are required.' });
        if (!ALLOWED_PRAYERS.includes(prayerName)) return res.status(400).json({ error: `prayerName must be one of: ${ALLOWED_PRAYERS.join(', ')}` });

        // helper to format to 12h (reuse if you already have one)
        function to12Hour(timeStr) {
            if (!timeStr) return null;
            const [h, m] = timeStr.split(':').map(Number);
            const ampm = h >= 12 ? 'PM' : 'AM';
            const hour12 = (h % 12) || 12;
            return `${hour12}:${String(m).padStart(2,'0')} ${ampm}`;
        }

        // ensure checklist rows exist for today (so we can update)
        await new Promise((resolve, reject) => ensurePrayerStatusRows(userId, date, (e) => e ? reject(e) : resolve()));

        // get today's prayer times (if missing, attempt to auto-save using server location)
        let timesRow = await dbGet('SELECT * FROM prayer_times WHERE user_id = ? AND date = ?', [userId, date]);

        if (!timesRow) {
            // attempt to determine location and auto-save prayer times (same logic as /prayer-times/save)
            let lat, lon;
            try {
                const loc = await getLocation();
                if (loc && typeof loc.latitude === 'number' && typeof loc.longitude === 'number') {
                    lat = loc.latitude; lon = loc.longitude;
                }
            } catch (locErr) {
                console.warn('Auto getLocation failed:', locErr && locErr.message);
            }

            if (!lat || !lon) {
                return res.status(400).json({ error: 'No prayer times for today and server cannot determine location. Please save prayer times first.' });
            }

            const calcDate = new Date(`${date}T12:00:00`); // use midday to avoid DST edge cases
            const times = calculatePrayerTimesForDate(lat, lon, calcDate);

            // insert (or upsert)
            await dbRunP(
                `INSERT INTO prayer_times (user_id, date, fajr, shurooq, dhuhr, asr, maghrib, isha)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, date) DO UPDATE SET
           fajr=excluded.fajr, shurooq=excluded.shurooq, dhuhr=excluded.dhuhr,
           asr=excluded.asr, maghrib=excluded.maghrib, isha=excluded.isha`,
                [userId, date, times.fajr, times.shurooq, times.dhuhr, times.asr, times.maghrib, times.isha]
            );

            timesRow = await dbGet('SELECT * FROM prayer_times WHERE user_id = ? AND date = ?', [userId, date]);
            if (!timesRow) return res.status(500).json({ error: 'Failed to create prayer times for today.' });
        }

        // scheduled time for this prayer (string like "18:58:00")
        const scheduledStr = timesRow[prayerName];
        if (!scheduledStr) return res.status(500).json({ error: `Scheduled time missing for ${prayerName}` });

        // build Date objects in local time (YYYY-MM-DDTHH:MM:SS)
        const scheduled = new Date(`${date}T${scheduledStr}`);
        if (isNaN(scheduled.getTime())) return res.status(500).json({ error: `Could not parse scheduled time: ${scheduledStr}` });

        const now = new Date();

        // prevent marking early
        if (now < scheduled) {
            return res.status(403).json({ error: `You cannot mark ${prayerName} before its time (${to12Hour(scheduledStr)})` });
        }

        // determine the "next" prayer start time
        const idx = ALLOWED_PRAYERS.indexOf(prayerName);
        let nextStart = null;
        if (idx !== -1 && idx < ALLOWED_PRAYERS.length - 1) {
            const nextName = ALLOWED_PRAYERS[idx + 1];
            const nextStr = timesRow[nextName];
            if (nextStr) {
                nextStart = new Date(`${date}T${nextStr}`);
            }
        }

        // status logic: late if current time >= next prayer start; otherwise on_time
        const status = (nextStart && now >= nextStart) ? 'late' : 'on_time';

        // update prayer_status -> mark as done and set status
        const updateSql = `
      UPDATE prayer_status
      SET done = 1, done_at = datetime('now'), status = ?
      WHERE user_id = ? AND date = ? AND prayer_name = ? AND done = 0
    `;
        const updateRes = await dbRunP(updateSql, [status, userId, date, prayerName]);

        if (updateRes.changes === 1) {
            const ts = new Date().toISOString();
            await dbRunP(
                `INSERT INTO prayer_log (user_id, prayer_name, action, status, timestamp) VALUES (?, ?, 'marked', ?, ?)`,
                [userId, prayerName, status, ts]
            );
            return res.json({ message: `Prayer marked as ${status}.`, prayerName, status, date });
        }

        // nothing changed -> already marked
        return res.status(409).json({ error: 'Prayer already marked for this date.' });

    } catch (err) {
        console.error('POST /prayers/mark error:', err);
        return res.status(500).json({ error: err.message || 'Failed to mark prayer' });
    }
});



// Auth routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Redirect to the frontend after successful login
        res.redirect('/');
    }
);

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

// Export app for testing/other modules (optional)
module.exports = app;

// Prayer History API
app.get('/api/history/:userId', (req, res) => {
    const userId = Number(req.params.userId);
    if (!userId) return res.status(400).json({ error: "Invalid userId" });

    const { start, end } = req.query;

    // Default: last 7 days
    let sql = `SELECT * FROM prayer_log WHERE user_id = ?`;
    const params = [userId];

    if (start && end) {
        sql += ` AND date(timestamp) BETWEEN date(?) AND date(?)`;
        params.push(start, end);
    } else {
        sql += ` AND date(timestamp) >= date('now', '-7 days')`;
    }

    sql += ` ORDER BY timestamp DESC`;

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ userId, history: rows });
    });
});

// Group API
app.post('/api/groups', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    const { name } = req.body;
    const ownerId = req.user.id;
    if (!name) return res.status(400).json({ error: "Group name is required" });

    try {
        const result = await dbRunP('INSERT INTO groups (name, owner_id) VALUES (?, ?)', [name, ownerId]);
        await dbRunP('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [result.lastID, ownerId]);
        res.status(201).json({ id: result.lastID, name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    try {
        const groups = await dbAllP('SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?', [req.user.id]);
        res.json(groups);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups/:groupId', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    const groupId = Number(req.params.groupId);
    if (!groupId) return res.status(400).json({ error: "Invalid groupId" });

    try {
        // First, check if the current user is a member of this group to authorize access
        const memberCheck = await dbGet('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, req.user.id]);
        if (!memberCheck) {
            return res.status(403).json({ error: "You are not a member of this group." });
        }

        const members = await dbAllP('SELECT u.id, u.name FROM users u JOIN group_members gm ON u.id = gm.user_id WHERE gm.group_id = ?', [groupId]);
        const prayerStatus = await dbAllP('SELECT ps.*, u.name as userName FROM prayer_status ps JOIN group_members gm ON ps.user_id = gm.user_id JOIN users u ON ps.user_id = u.id WHERE gm.group_id = ? AND ps.date = ? ORDER BY ps.user_id', [groupId, getLocalDateYMD()]);
        res.json({ members, prayerStatus });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Nightly job: auto-mark not_done
cron.schedule('5 0 * * *', () => {
    const yesterday = getLocalDateYMD(new Date(Date.now() - 86400000));
    console.log(`⏰ Nightly check: finalizing prayers for ${yesterday}`);

    db.all(`SELECT * FROM prayer_status WHERE date=? AND done=0`, [yesterday], (err, rows) => {
        if (err) return console.error('Nightly check DB error:', err.message);

        rows.forEach(row => {
            // mark as not_done
            db.run(
                `UPDATE prayer_status SET done=0, done_at=NULL, status='not_done' WHERE id=?`,
                [row.id],
                (uErr) => {
                    if (uErr) console.error('Update failed:', uErr.message);
                }
            );

            // log it
            const ts = new Date().toISOString();
            db.run(
                `INSERT INTO prayer_log (user_id, prayer_name, action, status, timestamp) VALUES (?, ?, 'auto_mark', 'not_done', ?)`,
                [row.user_id, row.prayer_name, ts],
                (iErr) => {
                    if (iErr) console.error('Insert log failed:', iErr.message);
                }
            );
        });
    });
});

// Start server
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} already in use.`);
        process.exit(1);
    } else {
        console.error('Server error:', err);
    }
});