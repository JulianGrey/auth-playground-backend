require('dotenv').config();

const cookieParser = require('cookie-parser');
const cors = require('cors');
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3001;

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3135',
  credentials: true
}));

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost/auth_demo'
});

function authenticateToken(req, res, next) {
  // const authHeader = req.headers['authorization'];
  // const token = authHeader && authHeader.split(' ')[1]; // Expect "Bearer <token>"

  const token = req.cookies.token;

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user; // user info from token payload
    next();
  });
}

// User registration endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    // Hash the password
    const saltRounds = 10;
    const password_hash = await bcrypt.hash(password, saltRounds);
    // Insert user into database
    await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
      [username, password_hash]
    );
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    if (err.code === '23505') { // unique_violation
      res.status(409).json({ error: 'Username already exists.' });
    } else {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
});

app.post('/login', async (req, res) => {
  const errorMessage = 'There was a problem with login';
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    const user = result.rows[0];

    if (user) {
      const authenticatedUser = await bcrypt.compare(password, user.password_hash);
  
      if (authenticatedUser) {
        const token = jwt.sign(
          { userId: user.id, username: user.username },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        // For HTTP-only cookie
        // An HTTP-only cookie cannot be interacted with using JavaScript
        // If using HTTP-only, remove the { token } from the { .json() } response
        res.cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000
        });
        // return res.status(200).json({ message: 'Login successful', token });
        return res.status(200).json({ message: 'Login successful' });
      }
    }
    return res.status(401).json({ message: errorMessage });
  } catch (err) {
    console.error('Login error: ', err);
    return res.status(500).json({ message: errorMessage });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ message: 'Logged out successfully' });
});

app.get('/user', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
