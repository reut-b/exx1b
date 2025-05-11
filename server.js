//Submitters' names:
// 323089714 - Liraz
// 207515768 - Reut
// 323516682 - Margarita
// repo link - https://github.com/reut-b/exx1b
// date: 09-05-2025
// Description: Server for personal profile website using Node.js and EJS

// Import required modules
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fileUpload = require("express-fileupload");
const fs = require("fs");

// Create express application
const app = express();

// Middleware configuration
app.use(express.static("public")); // Serve static files
app.use(bodyParser.urlencoded({ extended: true })); // Parse form data
app.set("view engine", "ejs"); // Set EJS as template engine

// Middleware for file upload
app.use(fileUpload());

// Middleware for session management
app.use(
  session({
    secret: "my-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Create uploads folder if it does not exist
if (!fs.existsSync("./uploads")) {
  fs.mkdirSync("./uploads");
}

// Connect to SQLite database
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
  } else {
    console.log("Connected to SQLite database");

    // Create users table if it does not exist
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      firstName TEXT NOT NULL,
      lastName TEXT NOT NULL,
      email TEXT NOT NULL,
      birthDate TEXT NOT NULL,
      profilePicture TEXT NOT NULL
    )`,
      (err) => {
        if (err) {
          console.error("Error creating table:", err);
        } else {
          console.log("Users table is ready");
        }
      }
    );
  }
});

// Middleware to check if the user is logged in
function checkLoggedIn(req, res, next) {
  if (req.session.user) {
    next(); // User is logged in, proceed to next middleware
  } else {
    res.redirect("/login"); // User not logged in, redirect to login page
  }
}

// Routes

// Root route - redirect to home if logged in, otherwise to login
app.get("/", (req, res) => {
  if (req.session.user) {
    res.redirect("/home");
  } else {
    res.redirect("/login");
  }
});

// Login page
app.get("/login", (req, res) => {
  // If the user is already logged in, redirect to home
  if (req.session.user) {
    res.redirect("/home");
  } else {
    res.render("login", { error: null });
  }
});

// Handle login form submission
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Check if all fields are filled
  if (!username || !password) {
    return res.render("login", { error: "Please fill in all fields" });
  }

  // Find user in the database
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.render("login", { error: "Error searching for user" });
    }

    // If user does not exist
    if (!user) {
      return res.render("login", { error: "Incorrect username or password" });
    }

    // Compare hashed password
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        return res.render("login", { error: "Error checking password" });
      }

      if (match) {
        // Store user details in session
        req.session.user = {
          id: user.id,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          birthDate: user.birthDate,
          profilePicture: user.profilePicture,
        };
        return res.redirect("/home");
      } else {
        return res.render("login", { error: "Incorrect username or password" });
      }
    });
  });
});

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

// Handle signup form submission
app.post("/signup", (req, res) => {
  const { username, password, firstName, lastName, email, birthDate } =
    req.body;

  // Check if all fields are filled
  if (
    !username ||
    !password ||
    !firstName ||
    !lastName ||
    !email ||
    !birthDate
  ) {
    return res.render("signup", { error: "Please fill in all fields" });
  }

  // Check if profile picture was uploaded
  if (!req.files || !req.files.profilePicture) {
    return res.render("signup", { error: "Please upload a profile picture" });
  }

  // Check if the username already exists
  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, existingUser) => {
      if (err) {
        return res.render("signup", { error: "Error checking username" });
      }

      if (existingUser) {
        return res.render("signup", { error: "Username already exists" });
      }

      // Handle profile picture upload
      const profilePic = req.files.profilePicture;
      const picFileName =
        Date.now() + "_" + username + path.extname(profilePic.name);
      const uploadPath = "./uploads/" + picFileName;

      profilePic.mv(uploadPath, (err) => {
        if (err) {
          return res.render("signup", { error: "Error uploading image" });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            return res.render("signup", { error: "Error hashing password" });
          }

          // Save the user to the database
          db.run(
            "INSERT INTO users (username, password, firstName, lastName, email, birthDate, profilePicture) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
              username,
              hashedPassword,
              firstName,
              lastName,
              email,
              birthDate,
              picFileName,
            ],
            function (err) {
              if (err) {
                return res.render("signup", { error: "Error saving user" });
              }

              // Redirect to login page
              res.redirect("/login");
            }
          );
        });
      });
    }
  );
});

// Home page (protected - only for logged in users)
app.get("/home", checkLoggedIn, (req, res) => {
  res.render("home", { user: req.session.user });
});

// Serve profile image (protected - only for the logged-in user's image)
app.get("/profile-image/:filename", checkLoggedIn, (req, res) => {
  const requestedFile = req.params.filename;

  // Make sure user requests only their own picture
  if (requestedFile === req.session.user.profilePicture) {
    res.sendFile(path.join(__dirname, "uploads", requestedFile));
  } else {
    res.status(403).send("You are not authorized to view this image");
  }
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});