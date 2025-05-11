const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const path = require("path");

const DB_PATH = path.join(__dirname, "users.db");
const db = new sqlite3.Database(DB_PATH);

function createUsersTable() {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uname TEXT UNIQUE NOT NULL,
      passwd TEXT NOT NULL,
      fname TEXT NOT NULL,
      lname TEXT NOT NULL,
      email TEXT NOT NULL,
      birth TEXT NOT NULL,
      pfp TEXT
    )`
  );
}

function addUser(info, cb) {
  bcrypt.hash(info.passwd, 10, (err, hash) => {
    if (err) return cb(err);
    db.run(
      "INSERT INTO users (uname, passwd, fname, lname, email, birth, pfp) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        info.uname,
        hash,
        info.fname,
        info.lname,
        info.email,
        info.birth,
        info.pfp,
      ],
      function (err) {
        if (err) return cb(err);
        cb(null, { id: this.lastID, ...info });
      }
    );
  });
}

function authUser(uname, passwd, cb) {
  db.get("SELECT * FROM users WHERE uname = ?", [uname], (err, u) => {
    if (err) return cb(err);
    if (!u) return cb(null, false);
    bcrypt.compare(passwd, u.passwd, (err, ok) => {
      if (err) return cb(err);
      if (ok) {
        const { passwd, ...user } = u;
        cb(null, user);
      } else {
        cb(null, false);
      }
    });
  });
}

function getUserById(id, cb) {
  db.get(
    "SELECT id, uname, fname, lname, email, birth, pfp FROM users WHERE id = ?",
    [id],
    (err, u) => {
      if (err) return cb(err);
      cb(null, u);
    }
  );
}

module.exports = {
  createUsersTable,
  addUser,
  authUser,
  getUserById,
};
