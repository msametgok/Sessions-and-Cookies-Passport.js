import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());  // Add cookie-parser middleware

// Database connection
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();

// JWT Middleware to protect routes
function authenticateJWT(req, res, next) {
  const token = req.cookies.token; // Get the token from cookies

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403); // Forbidden
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401); // Unauthorized
  }
}

// Routes
app.get("/", (req, res) => res.render("home.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));

app.get('/secrets', authenticateJWT, (req, res) => {
  res.render('secrets.ejs');
});

app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;

  try {
    const userExists = await checkUserExists(email);
    if (userExists) {
      res.send("Email already exists. Try logging in.");
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUser = await createUser(email, hashedPassword);

      // Automatically log in the user by generating a JWT
      const token = generateJWT(newUser);

      // Store the token in a cookie and redirect to secrets
      res.cookie('token', token, { httpOnly: true });
      res.redirect('/secrets');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.post("/login", async (req, res) => {
  const { username: email, password } = req.body;

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Generate a JWT token for the user
    const token = generateJWT(user);

    // Store the token in a cookie and redirect to secrets
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/secrets');
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Helper function to generate a JWT
function generateJWT(user) {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: '1h'
  });
}

// Helper functions for database queries
async function checkUserExists(email) {
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  return result.rows.length > 0;
}

async function createUser(email, password) {
  const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, password]);
  return result.rows[0];
}

async function getUserByEmail(email) {
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  return result.rows[0];
}

async function getUserById(id) {
  const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
  return result.rows[0];
}

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
