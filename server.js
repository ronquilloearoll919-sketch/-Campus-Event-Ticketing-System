const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const SECRET = 'campus-tix-secret-key-2026';
const SALT_ROUNDS = 10;
const DB_PATH = 'ticketing.db';

let db;

// ---------- Initialize SQLite via sql.js ----------
async function initDB() {
  const SQL = await initSqlJs();
  // Try to load existing database file
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  // Create tables if they don't exist
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      school_id TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('student','organizer','gate_staff')) NOT NULL DEFAULT 'student',
      photo_url TEXT DEFAULT ''
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      date TEXT NOT NULL,
      venue TEXT DEFAULT '',
      price REAL NOT NULL,
      total_slots INTEGER NOT NULL,
      description TEXT DEFAULT '',
      created_by INTEGER REFERENCES users(id)
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_code TEXT UNIQUE NOT NULL,
      event_id INTEGER REFERENCES events(id),
      user_id INTEGER REFERENCES users(id),
      status TEXT CHECK(status IN ('valid','used','cancelled','pending_payment')) DEFAULT 'pending_payment',
      purchased_at TEXT DEFAULT (datetime('now')),
      scanned_at TEXT
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER REFERENCES tickets(id),
      scanned_by INTEGER REFERENCES users(id),
      scan_time TEXT DEFAULT (datetime('now')),
      gate_location TEXT DEFAULT ''
    );
  `);
  saveDB();
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// ---------- Seed default users & events if empty ----------
function seedData() {
  const userCount = db.exec("SELECT COUNT(*) as cnt FROM users");
  if (userCount[0]?.values[0][0] === 0) {
    const defaultUsers = [
      { school_id: '2024-001', full_name: 'Juan dela Cruz', email: 'juan@student.edu', password: 'password123', role: 'student' },
      { school_id: 'org-001', full_name: 'Admin Organizer', email: 'admin@school.edu', password: 'admin123', role: 'organizer' },
      { school_id: 'gate-001', full_name: 'Gate Staff', email: 'gate@school.edu', password: 'gate123', role: 'gate_staff' }
    ];
    const stmt = db.prepare("INSERT INTO users (school_id, full_name, email, password_hash, role) VALUES (?,?,?,?,?)");
    for (const u of defaultUsers) {
      stmt.run([u.school_id, u.full_name, u.email, bcrypt.hashSync(u.password, SALT_ROUNDS), u.role]);
    }
    stmt.free();
    // Seed events
    const insertEvent = db.prepare("INSERT INTO events (name, date, venue, price, total_slots, description, created_by) VALUES (?,?,?,?,?,?,?)");
    insertEvent.run(['Foundation Day Concert', '2026-05-20', 'Main Auditorium', 50, 500, 'A grand concert for foundation day.', 2]);
    insertEvent.run(['Intrams Opening', '2026-06-05', 'Gymnasium', 30, 300, 'Kickoff of intramurals.', 2]);
    insertEvent.free();
    saveDB();
  }
}

// ---------- Middleware: authenticate JWT ----------
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded; // { id, school_id, role, full_name }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- AUTH ROUTES ----------
app.post('/api/login', (req, res) => {
  const { school_id, password } = req.body;
  if (!school_id || !password) return res.status(400).json({ error: 'Missing credentials' });
  const result = db.exec("SELECT * FROM users WHERE school_id = ?", [school_id]);
  if (result.length === 0 || result[0].values.length === 0) return res.status(401).json({ error: 'User not found' });
  const user = result[0].values[0];
  const userObj = {
    id: user[0], school_id: user[1], full_name: user[2], email: user[3],
    password_hash: user[4], role: user[5], photo_url: user[6]
  };
  if (!bcrypt.compareSync(password, userObj.password_hash))
    return res.status(401).json({ error: 'Incorrect password' });
  const token = jwt.sign({ id: userObj.id, school_id: userObj.school_id, role: userObj.role, full_name: userObj.full_name }, SECRET, { expiresIn: '8h' });
  res.json({ token, user: { id: userObj.id, school_id: userObj.school_id, role: userObj.role, full_name: userObj.full_name, email: userObj.email } });
});

// ---------- DASHBOARD STATS ----------
app.get('/api/stats', authenticate, (req, res) => {
  try {
    const validTickets = db.exec("SELECT COUNT(*) as count FROM tickets WHERE status = 'valid'");
    const totalSlots = db.exec("SELECT SUM(total_slots) as total FROM events");
    const revenue = db.exec("SELECT SUM(e.price) as total FROM tickets t JOIN events e ON t.event_id = e.id WHERE t.status != 'cancelled'");
    const activeEvents = db.exec("SELECT COUNT(*) as count FROM events WHERE date >= date('now')");

    res.json({
      totalTickets: validTickets[0]?.values[0][0] || 0,
      totalSlots: totalSlots[0]?.values[0][0] || 0,
      revenue: revenue[0]?.values[0][0] || 0,
      activeEvents: activeEvents[0]?.values[0][0] || 0
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- EVENTS ----------
app.get('/api/events', authenticate, (req, res) => {
  const events = db.exec("SELECT * FROM events");
  const rows = events.length > 0 ? events[0].values.map(row => ({
    id: row[0], name: row[1], date: row[2], venue: row[3], price: row[4],
    total_slots: row[5], description: row[6], created_by: row[7]
  })) : [];
  res.json(rows);
});

app.post('/api/events', authenticate, (req, res) => {
  if (req.user.role !== 'organizer') return res.status(403).json({ error: 'Forbidden' });
  const { name, date, venue, price, total_slots, description } = req.body;
  if (!name || !date || !price || !total_slots) return res.status(400).json({ error: 'Missing fields' });
  const stmt = db.prepare("INSERT INTO events (name, date, venue, price, total_slots, description, created_by) VALUES (?,?,?,?,?,?,?)");
  stmt.run([name, date, venue, price, total_slots, description, req.user.id]);
  stmt.free();
  saveDB();
  res.status(201).json({ message: 'Event created' });
});

// ---------- TICKETS ----------
app.get('/api/tickets', authenticate, (req, res) => {
  let rows;
  if (req.user.role === 'organizer' || req.user.role === 'gate_staff') {
    const result = db.exec(`
      SELECT t.*, u.full_name as student_name, e.name as event_name
      FROM tickets t
      JOIN users u ON t.user_id = u.id
      JOIN events e ON t.event_id = e.id
    `);
    rows = result.length > 0 ? result[0].values : [];
  } else {
    const result = db.exec(`
      SELECT t.*, e.name as event_name
      FROM tickets t
      JOIN events e ON t.event_id = e.id
      WHERE t.user_id = ?
    `, [req.user.id]);
    rows = result.length > 0 ? result[0].values : [];
  }
  const tickets = rows.map(row => ({
    id: row[0], ticket_code: row[1], event_id: row[2], user_id: row[3],
    status: row[4], purchased_at: row[5], scanned_at: row[6],
    student_name: row[7] || null, event_name: row[req.user.role === 'student' ? 7 : 8]
  }));
  res.json(tickets);
});

app.post('/api/tickets', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Only students can buy tickets' });
  const { event_id, quantity = 1 } = req.body;
  if (!event_id) return res.status(400).json({ error: 'Missing event_id' });
  const eventResult = db.exec("SELECT * FROM events WHERE id = ?", [event_id]);
  if (eventResult.length === 0 || eventResult[0].values.length === 0) return res.status(404).json({ error: 'Event not found' });
  const event = eventResult[0].values[0];
  const soldResult = db.exec("SELECT COUNT(*) as count FROM tickets WHERE event_id = ? AND status != 'cancelled'", [event_id]);
  const sold = soldResult[0]?.values[0][0] || 0;
  if (sold + quantity > event[5]) return res.status(400).json({ error: 'Not enough slots available' });
  const stmt = db.prepare("INSERT INTO tickets (ticket_code, event_id, user_id, status) VALUES (?,?,?,?)");
  const ticketsCreated = [];
  for (let i = 0; i < quantity; i++) {
    const code = 'TKT-' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2,4).toUpperCase();
    stmt.run([code, event_id, req.user.id, 'valid']);
    ticketsCreated.push(code);
  }
  stmt.free();
  saveDB();
  res.status(201).json({ tickets: ticketsCreated });
});

app.post('/api/validate', authenticate, (req, res) => {
  if (req.user.role !== 'gate_staff') return res.status(403).json({ error: 'Only gate staff can validate' });
  const { ticket_code } = req.body;
  if (!ticket_code) return res.status(400).json({ error: 'Missing ticket_code' });
  const result = db.exec(`
    SELECT t.*, u.full_name, u.school_id, u.photo_url, e.name, e.date
    FROM tickets t
    JOIN users u ON t.user_id = u.id
    JOIN events e ON t.event_id = e.id
    WHERE t.ticket_code = ?
  `, [ticket_code]);
  if (result.length === 0 || result[0].values.length === 0) return res.status(404).json({ error: 'Ticket not found' });
  const t = result[0].values[0];
  const ticket = { id: t[0], ticket_code: t[1], status: t[4], student_name: t[7], event_name: t[9] };
  if (ticket.status === 'used') return res.status(400).json({ error: 'Ticket already used' });
  if (ticket.status !== 'valid') return res.status(400).json({ error: 'Ticket is not valid: ' + ticket.status });
  db.run("UPDATE tickets SET status = 'used', scanned_at = datetime('now') WHERE id = ?", [ticket.id]);
  db.run("INSERT INTO scan_logs (ticket_id, scanned_by) VALUES (?,?)", [ticket.id, req.user.id]);
  saveDB();
  res.json({ message: 'Ticket validated successfully', student_name: ticket.student_name, event: ticket.event_name });
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  seedData();
  console.log(`Server running on http://localhost:${PORT}`);
  app.listen(PORT);
}).catch(err => {
  console.error('Failed to initialize database:', err);
});