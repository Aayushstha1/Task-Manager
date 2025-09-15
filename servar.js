const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

// SQLite database setup
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite database.");
});

// Create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'Assigned',
    assigned_to INTEGER,
    assigned_by INTEGER,
    FOREIGN KEY(assigned_to) REFERENCES users(id),
    FOREIGN KEY(assigned_by) REFERENCES users(id)
  )`);

  // Insert default admin
  db.get(`SELECT * FROM users WHERE role='admin'`, (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync("admin123", 10);
      db.run(
        `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
        ["admin", hashed, "admin"]
      );
      console.log("Default admin created: username=admin, password=admin123");
    }
  });
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username=?`, [username], (err, user) => {
    if (err || !user) return res.status(401).send("Invalid credentials");

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).send("Invalid credentials");
    }

    req.session.user = user;
    res.json({ role: user.role });
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Admin: Create Employee
app.post("/admin/create-employee", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access denied");

  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
    [username, hashed, "employee"],
    function (err) {
      if (err) return res.status(400).send("User already exists");
      res.send("Employee created successfully");
    }
  );
});

// Admin: Assign Task
app.post("/admin/assign-task", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access denied");

  const { title, description, employeeId } = req.body;

  db.run(
    `INSERT INTO tasks (title, description, assigned_to, assigned_by) VALUES (?, ?, ?, ?)`,
    [title, description, employeeId, req.session.user.id],
    function (err) {
      if (err) return res.status(400).send("Error assigning task");
      res.send("Task assigned successfully");
    }
  );
});

// Employee: Submit Task
app.post("/employee/submit-task", (req, res) => {
  if (!req.session.user || req.session.user.role !== "employee")
    return res.status(403).send("Access denied");

  const { taskId } = req.body;

  db.run(
    `UPDATE tasks SET status='Completed' WHERE id=? AND assigned_to=?`,
    [taskId, req.session.user.id],
    function (err) {
      if (err || this.changes === 0)
        return res.status(400).send("Task not found or not yours");
      res.send("Task submitted successfully");
    }
  );
});

// Admin: Promote Employee
app.post("/admin/promote", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access denied");

  const { employeeId } = req.body;

  db.run(
    `UPDATE users SET role='admin' WHERE id=?`,
    [employeeId],
    function (err) {
      if (err || this.changes === 0) return res.status(400).send("Promotion failed");
      res.send("Employee promoted to admin");
    }
  );
});

// Get tasks (for both roles)
app.get("/tasks", (req, res) => {
  if (!req.session.user) return res.status(403).send("Not logged in");

  if (req.session.user.role === "admin") {
    db.all(`SELECT * FROM tasks`, [], (err, rows) => {
      res.json(rows);
    });
  } else {
    db.all(
      `SELECT * FROM tasks WHERE assigned_to=?`,
      [req.session.user.id],
      (err, rows) => {
        res.json(rows);
      }
    );
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
