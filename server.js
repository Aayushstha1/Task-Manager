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
    role TEXT,
    employee_id TEXT UNIQUE
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

  // Insert default admin if not exists
  db.get(`SELECT * FROM users WHERE role='admin'`, (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync("admin123", 10);
      db.run(
        `INSERT INTO users (username, password, role, employee_id) VALUES (?, ?, ?, ?)`,
        ["admin", hashed, "admin", "ADM001"]
      );
      console.log("Default admin created: username=admin, password=admin123");
    }
  });
});

// ----------------- LOGIN -----------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username=?`, [username], (err, user) => {
    if (err) return res.status(500).send("Server error");
    if (!user) return res.status(401).send("Invalid username or password");

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).send("Invalid username or password");
    }

    // Store only essential info in session
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      employee_id: user.employee_id || null,
    };

    res.json({ role: user.role });
  });
});

// ----------------- LOGOUT -----------------
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.send("Logged out successfully");
});

// ----------------- SIGNUP (Employee) -----------------
app.post("/signup", (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);

  db.get(`SELECT * FROM users WHERE username=?`, [username], (err, row) => {
    if (err) return res.status(500).send("Server error");
    if (row) return res.status(400).send("User already exists");

    // Generate a safe employee ID (avoid duplicates)
    db.get(`SELECT MAX(id) as maxId FROM users`, [], (err, row2) => {
      if (err) return res.status(500).send("Server error");
      const empId = "EMP" + String((row2?.maxId || 0) + 1).padStart(3, "0");

      db.run(
        `INSERT INTO users (username, password, role, employee_id) VALUES (?, ?, ?, ?)`,
        [username, hashed, "employee", empId],
        function (err) {
          if (err) return res.status(500).send("Signup failed: " + err.message);
          res.send(`Employee registered successfully! Your ID: ${empId}`);
        }
      );
    });
  });
});

// ----------------- GET LOGGED-IN USER INFO -----------------
app.get("/me", (req, res) => {
  if (!req.session.user) return res.status(403).send("Not logged in");
  res.json(req.session.user);
});

// ----------------- ADMIN: GET EMPLOYEES -----------------
app.get("/admin/employees", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access denied");

  db.all(`SELECT id, username, employee_id FROM users WHERE role='employee'`, [], (err, rows) => {
    if (err) return res.status(500).send("Error fetching employees");
    res.json(rows);
  });
});

// ----------------- ADMIN: ASSIGN TASK -----------------
app.post("/admin/assign-task", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).send("Access denied");

  const { title, description, employeeId } = req.body;

  // Get internal ID of employee
  db.get(`SELECT id FROM users WHERE employee_id=?`, [employeeId], (err, emp) => {
    if (err || !emp) return res.status(400).send("Employee not found");

    db.run(
      `INSERT INTO tasks (title, description, assigned_to, assigned_by) VALUES (?, ?, ?, ?)`,
      [title, description, emp.id, req.session.user.id],
      function (err) {
        if (err) return res.status(500).send("Error assigning task");
        res.send("Task assigned successfully");
      }
    );
  });
});

// ----------------- EMPLOYEE: SUBMIT TASK -----------------
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
      res.send("Task marked as completed!");
    }
  );
});

// ----------------- GET TASKS -----------------
app.get("/tasks", (req, res) => {
  if (!req.session.user) return res.status(403).send("Not logged in");

  if (req.session.user.role === "admin") {
    db.all(
      `SELECT t.id, t.title, t.description, t.status, u.username as assigned_to_name, a.username as assigned_by_name
       FROM tasks t
       LEFT JOIN users u ON t.assigned_to = u.id
       LEFT JOIN users a ON t.assigned_by = a.id`,
      [],
      (err, rows) => res.json(rows)
    );
  } else {
    db.all(
      `SELECT id, title, description, status FROM tasks WHERE assigned_to=?`,
      [req.session.user.id],
      (err, rows) => res.json(rows)
    );
  }
});

// ----------------- SERVER -----------------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
