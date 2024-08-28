import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(passport.initialize());
app.use(passport.session());

// Database connection
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: 5432,
});
db.connect();

// Routes
app.get("/", (req, res) => res.render("home.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));

app.get('/secrets', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('secrets.ejs');
  } else {
    res.redirect('/login');
  }
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
      req.login(newUser, err => {
        if (err) console.error(err);
        res.redirect('/secrets');
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.post("/login", passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));

// Passport Local Strategy
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await getUserByEmail(username);
    if (!user) return done(null, false, { message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) return done(null, user);
    return done(null, false, { message: 'Incorrect password' });
  } catch (err) {
    return done(err);
  }
}));

// Passport serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await getUserById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Helper functions
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
