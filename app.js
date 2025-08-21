const express = require("express");
const router = express.Router(); // changes #rohit
const bodyParser = require("body-parser");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { Pool } = require("pg");
const multer = require("multer"); // Add multer
const path = require("path"); // For file path handling
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const app = express();
const port = 4000;

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// PostgreSQL connection
// NOTE: use YOUR postgres username and password here
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "sr_system",
  password: "rohit",
  port: 5432,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// CORS: Give permission to localhost:3000 (ie our React app)
// to use this backend API
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

// Session information
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Store files in 'uploads/' folder
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});
const upload = multer({ storage: storage });

// Serve uploaded files statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/////////////////////////////////////////////////////////////
// Authentication APIs
// Signup, Login, IsLoggedIn and Logout
app.get('/', (req, res) => {
  res.send('Backend is running');
});
// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

// Add after your existing imports
const generatePin = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Modify your signup endpoint to not set session immediately
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1;",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Error: Email is already registered." });
    }

    // Insert user with is_verified set to false
    await pool.query(
      "INSERT INTO users (username, email, password_hash, is_verified) VALUES ($1, $2, $3, FALSE);",
      [username, email, hashedPassword]
    );

    // Generate and send verification PIN
    const pin = generatePin();
    const expiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes from now

    await pool.query(
      "INSERT INTO verification_pins (email, pin, expires_at) VALUES ($1, $2, $3)",
      [email, pin, expiresAt]
    );

    // Setup nodemailer
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "prakashsrathod0@gmail.com",
        pass: "saof cqlv bzlw aiec",
      },
    });

    const mailOptions = {
      from: "prakashsrathod0@gmail.com",
      to: email,
      subject: "Email Verification PIN",
      html: `
        <h1>Welcome to Our Platform</h1>
        <p>Your verification PIN is: <strong>${pin}</strong></p>
        <p>This PIN will expire in 10 minutes.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({ 
      message: "User registered successfully. Please check your email for verification PIN.",
      email: email
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error signing up" });
  }
});

// Add new endpoint for PIN verification
app.post("/verify-email", async (req, res) => {
  const { email, pin } = req.body;

  try {
    // Check if PIN exists and is valid
    const pinResult = await pool.query(
      "SELECT * FROM verification_pins WHERE email = $1 AND pin = $2 AND expires_at > NOW()",
      [email, pin]
    );

    if (pinResult.rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired PIN" });
    }

    // Update user verification status
    await pool.query(
      "UPDATE users SET is_verified = TRUE WHERE email = $1",
      [email]
    );

    // Delete used PIN
    await pool.query(
      "DELETE FROM verification_pins WHERE email = $1",
      [email]
    );

    // Get user details and set session
    const userResult = await pool.query(
      "SELECT user_id, username FROM users WHERE email = $1",
      [email]
    );

    if (userResult.rows.length > 0) {
      req.session.userId = userResult.rows[0].user_id;
      req.session.username = userResult.rows[0].username;
    }

    res.json({ message: "Email verified successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error verifying email" });
  }
});

// Add endpoint to resend verification PIN
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;

  try {
    // Check if user exists and is not verified
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1 AND is_verified = FALSE",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ 
        message: "User not found or already verified" 
      });
    }

    // Generate new PIN
    const pin = generatePin();
    const expiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes from now

    // Delete any existing PINs for this email
    await pool.query(
      "DELETE FROM verification_pins WHERE email = $1",
      [email]
    );

    // Insert new PIN
    await pool.query(
      "INSERT INTO verification_pins (email, pin, expires_at) VALUES ($1, $2, $3)",
      [email, pin, expiresAt]
    );

    // Send new PIN via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "prakashsrathod0@gmail.com",
        pass: "saof cqlv bzlw aiec",
      },
    });

    const mailOptions = {
      from: "prakashsrathod0@gmail.com",
      to: email,
      subject: "New Email Verification PIN",
      html: `
        <h1>New Verification PIN</h1>
        <p>Your new verification PIN is: <strong>${pin}</strong></p>
        <p>This PIN will expire in 10 minutes.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "New verification PIN sent" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error resending verification PIN" });
  }
});

// Modify your login endpoint to check for verification
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1;",
      [email]
    );
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (!user.is_verified) {
        return res.status(403).json({ 
          message: "Please verify your email first",
          needsVerification: true,
          email: email
        });
      }

      req.session.userId = user.user_id;
      req.session.username = user.username;
      res.status(200).json({ message: "Login successful" });
    } else {
      res.status(400).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging in" });
  }
});

const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client("226426485757-bkm2dd6tful551ur1gphqoklgg9h5850.apps.googleusercontent.com");

app.post("/google-auth", async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: "226426485757-bkm2dd6tful551ur1gphqoklgg9h5850.apps.googleusercontent.com",
    });

    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    let userId;
    if (existingUser.rows.length > 0) {
      userId = existingUser.rows[0].user_id;
    } else {
      const insertRes = await pool.query(
        `INSERT INTO users (username, email, password_hash, auth_provider)
         VALUES ($1, $2, $3, $4)
         RETURNING user_id`,
        [name, email, null, 'google']
      );
      userId = insertRes.rows[0].user_id;
    }

    req.session.userId = userId;
    req.session.username = name;

    res.json({ success: true });
  } catch (err) {
    console.error("Google Auth Error:", err);
    res.status(401).json({ success: false, message: "Invalid Google token" });
  }
});
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userRes.rows[0];
    const token = jwt.sign({ userId: user.user_id }, "reset-secret", { expiresIn: "1h" });

    const resetLink = `http://localhost:3000/reset-password/${token}`;

    // Nodemailer setup
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "prakashsrathod0@gmail.com",
        pass: "saof cqlv bzlw aiec",
      },
    });

    const mailOptions = {
      from: "prakashsrathod0@gmail.com",
      to: email,
      subject: "Password Reset",
      text: `Click here to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "Password reset link sent" });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Error sending reset link" });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, "reset-secret");
    const hash = await bcrypt.hash(password, 10);
    
    await pool.query(
      "UPDATE users SET password_hash = $1 WHERE user_id = $2",
      [hash, decoded.userId]
    );

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(400).json({ message: "Invalid or expired token" });
  }
});
// server.js
app.get('/isLoggedIn', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }

  try {
    const result = await pool.query(
      'SELECT user_id, username, bio, profile_pic FROM users WHERE user_id = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    res.json({
      user_id: user.user_id,
      username: user.username,
      bio: user.bio,
      profile_pic: user.profile_pic ? `/uploads/${user.profile_pic}` : null,
    });
  } catch (err) {
    console.error('Error fetching logged-in user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: "Failed to log out" });
    res.clearCookie("connect.sid");
    res.status(200).json({ message: "Logged out successfully" });
  });
});

////////////////////////////////////////////////////
// Category & Item APIs

// Get all categories
app.get("/category", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM Categories;");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching categories" });
  }
});
 
app.get("/category/:categoryId/items", async (req, res) => {
  const { categoryId } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM Items WHERE category_id = $1;",
      [categoryId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ message: "Error fetching items" });
  }
});


// Get ratings for an item
app.get("/items/:itemId/ratings", async (req, res) => {
  const { itemId } = req.params;
  try {
    const result = await pool.query(
      `SELECT r.rating, r.review, u.username 
       FROM Ratings r 
       JOIN Users u ON r.user_id = u.user_id 
       WHERE r.item_id = $1;`,
      [itemId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching ratings" });
  }
});
// Get recommended items based on friends' ratings
app.get("/recommendations", async (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  try {
    const result = await pool.query(
      `SELECT i.*, COALESCE(AVG(r.rating), 0) AS avg_rating FROM Items i
       JOIN Ratings r ON i.item_id = r.item_id
       JOIN Friends f ON r.user_id = f.friend_id
       WHERE f.user_id = $1
       GROUP BY i.item_id
       ORDER BY avg_rating DESC LIMIT 10;`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching recommendations" });
  }
});
// 🔹 Fetch Reviews by Item
// Get reviews for an item
app.get('/item/:itemId/reviews', async (req, res) => {
  try {
    const userId = req.session.userId;
    const result = await pool.query(
      `SELECT 
         r.rating_id, 
         r.user_id, 
         r.rating, 
         r.review, 
         u.username, 
         u.profile_pic,
         r.user_id = $2 AS is_current_user
       FROM Ratings r
       JOIN Users u ON r.user_id = u.user_id
       WHERE r.item_id = $1`,
      [req.params.itemId, req.session.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching item reviews:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// 🔹 Add or Update Review
app.post("/item/:itemId/review", isAuthenticated, async (req, res) => {
  const { itemId } = req.params;
  const { rating, review } = req.body;
  const userId = req.session.userId;

  try {
    const existingReview = await pool.query(
      "SELECT * FROM Ratings WHERE user_id = $1 AND item_id = $2;",
      [userId, itemId]
    );

    if (existingReview.rows.length > 0) {
      // Update existing review
      await pool.query(
        "UPDATE Ratings SET rating = $1, review = $2 WHERE user_id = $3 AND item_id = $4;",
        [rating, review, userId, itemId]
      );
      return res.status(200).json({ message: "Review updated successfully" });
    } else {
      // Insert new review
      await pool.query(
        "INSERT INTO Ratings (user_id, item_id, rating, review) VALUES ($1, $2, $3, $4);",
        [userId, itemId, rating, review]
      );
      return res.status(201).json({ message: "Review added successfully" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error submitting review" });
  }
});

// 🔹 Update Review (PUT request)
app.put("/item/:itemId/review", isAuthenticated, async (req, res) => {
  const { itemId } = req.params;
  const { rating, review } = req.body;
  const userId = req.session.userId;

  try {
    const result = await pool.query(
      "UPDATE Ratings SET rating = $1, review = $2 WHERE user_id = $3 AND item_id = $4 RETURNING *;",
      [rating, review, userId, itemId]
    );

    if (result.rows.length > 0) {
      return res.status(200).json({ message: "Review updated successfully" });
    } else {
      return res.status(404).json({ message: "Review not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error updating review" });
  }
});

app.delete("/item/:itemId/review", async (req, res) => {
  const { itemId } = req.params;
  const username = req.session.username;

  if (!username) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    // ✅ Step 1: get user_id using correct column name
    const userResult = await pool.query(
      "SELECT user_id FROM users WHERE username = $1",
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userResult.rows[0].user_id;

    // ✅ Step 2: delete review using item_id and user_id
    const result = await pool.query(
      "DELETE FROM ratings WHERE item_id = $1 AND user_id = $2",
      [itemId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Review not found" });
    }

    res.status(200).json({ message: "Review deleted" });
  } catch (err) {
    console.error("Error deleting review:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// Comment on ratings
app.post("/ratings/:ratingId/comment", async (req, res) => {
  const { ratingId } = req.params;
  const { comment } = req.body;
  const userId = req.session.userId;

  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  try {
    await pool.query(
      "INSERT INTO Comments (user_id, rating_id, comment, created_at) VALUES ($1, $2, $3, NOW());",
      [userId, ratingId, comment]
    );
    res.status(201).json({ message: "Comment added successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error adding comment" });
  }
});

// Submit or update rating
app.post("/items/:itemId/rate", isAuthenticated, async (req, res) => {
  const { itemId } = req.params;
  const { rating, review } = req.body;
  const userId = req.session.userId;

  try {
    const existingRating = await pool.query(
      "SELECT * FROM Ratings WHERE user_id = $1 AND item_id = $2;",
      [userId, itemId]
    );

    if (existingRating.rows.length > 0) {
      // Update rating
      await pool.query(
        "UPDATE Ratings SET rating = $1, review = $2 WHERE user_id = $3 AND item_id = $4;",
        [rating, review, userId, itemId]
      );
      return res.status(200).json({ message: "Rating updated successfully" });
    } else {
      // Insert new rating
      await pool.query(
        "INSERT INTO Ratings (user_id, item_id, rating, review) VALUES ($1, $2, $3, $4);",
        [userId, itemId, rating, review]
      );
      return res.status(201).json({ message: "Rating submitted successfully" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error submitting rating" });
  }
});

app.get("/item/:itemId", async (req, res) => {
  const { itemId } = req.params;
  try {
    const result = await pool.query("SELECT * FROM Items WHERE item_id = $1", [itemId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Item not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching item by ID:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Send friend requests

app.post('/friends/request', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { friendId } = req.body;

  if (userId === friendId) {
    return res.status(400).json({ message: "Cannot send friend request to yourself" });
  }

  try {
    const existingRequest = await pool.query(
      'SELECT * FROM friends WHERE user_id = $1 AND friend_id = $2;',
      [userId, friendId]
    );

    if (existingRequest.rows.length > 0) {
      return res.status(400).json({ message: "Friend request already sent or accepted" });
    }

    await pool.query(
      'INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, $3);',
      [userId, friendId, 'pending']
    );
    res.status(201).json({ message: "Friend request sent successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error sending friend request" });
  }
});

// Accept friend requests

app.post('/friends/accept', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { friendId } = req.body;

  try {
    const result = await pool.query(
      'UPDATE friends SET status = $1 WHERE user_id = $2 AND friend_id = $3 AND status = $4 RETURNING *;',
      ['accepted', friendId, userId, 'pending']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No pending friend request found" });
    }

    res.status(200).json({ message: "Friend request accepted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error accepting friend request" });
  }
});

// Reject a pending friend request
app.post('/friends/reject', isAuthenticated, async (req, res) => {
  const userId = req.session.userId; // The user rejecting the request
  const { friendId } = req.body; // The user who sent the request

  try {
    const result = await pool.query(
      `DELETE FROM friends 
       WHERE user_id = $1 AND friend_id = $2 AND status = $3 
       RETURNING *;`,
      [friendId, userId, 'pending']
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "No pending friend request found" });
    }

    res.status(200).json({ message: "Friend request rejected successfully" });
  } catch (err) {
    console.error('Error rejecting friend request:', err);
    res.status(500).json({ message: "Error rejecting friend request" });
  }
});

// Get friends List

// app.get('/friends', isAuthenticated, async (req, res) => {
//   const userId = req.session.userId;

//   try {
//     const result = await pool.query(
//       `SELECT u.user_id, u.username, u.profile_pic, u.bio 
//        FROM friends f 
//        JOIN users u ON f.friend_id = u.user_id 
//        WHERE f.user_id = $1 AND f.status = $2;`,
//       [userId, 'accepted']
//     );
//     res.json(result.rows);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Error fetching friends list" });
//   }
// });

// Get Pending friend requests

app.get('/friends/pending', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }
  try {
    const result = await pool.query(
      'SELECT u.user_id, u.username, u.profile_pic ' +
      'FROM Friends f ' +
      'JOIN Users u ON f.user_id = u.user_id ' +
      'WHERE f.friend_id = $1 AND f.status = $2',
      [req.session.userId, 'pending']
    );
    console.log('Pending friend requests:', result.rows); // Debug log
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching pending requests:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/friends/status/:friendId', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { friendId } = req.params;
  try {
    const result = await pool.query(
      'SELECT status, user_id AS requester_id FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1);',
      [userId, friendId]
    );
    if (result.rows.length > 0) {
      const { status, requester_id } = result.rows[0];
      const direction = parseInt(requester_id) === parseInt(userId) ? 'sent' : 'received';
      res.json({ status, direction });
    } else {
      res.json({ status: 'none', direction: null });
    }
  } catch (err) {
    console.error('Error checking friend status:', err);
    res.status(500).json({ message: 'Error checking friend status' });
  }
});

// Update this endpoint in app.js
app.delete('/friends/request', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { friendId } = req.body;

  try {
    const result = await pool.query(
      `DELETE FROM friends 
       WHERE (user_id = $1 AND friend_id = $2 AND status = 'pending')
          OR (user_id = $2 AND friend_id = $1 AND status = 'pending')
          OR (user_id = $1 AND friend_id = $2 AND status = 'accepted')
          OR (user_id = $2 AND friend_id = $1 AND status = 'accepted')
       RETURNING *;`,
      [friendId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Friend request or friendship not found" });
    }

    res.status(200).json({ 
      message: result.rows[0].status === 'pending' 
        ? "Friend request rejected successfully" 
        : "Friendship removed successfully" 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error removing friend request or friendship" });
  }
});

app.post('/friends/unfollow', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { friendId } = req.body;

  try {
    const result = await pool.query(
      'DELETE FROM friends WHERE user_id = $1 AND friend_id = $2 AND status = $3',
      [userId, friendId, 'accepted']
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Friendship not found' });
    }
    res.status(200).json({ message: 'Successfully unfollowed user' });
  } catch (err) {
    console.error('Error unfollowing user:', err);
    res.status(500).json({ message: 'Error unfollowing user' });
  }
});

//01-05-2025

app.post('/friends/remove-follower', isAuthenticated, async (req, res) => {
  const userId = req.session.userId; // Current user (removing the follower)
  const { followerId } = req.body; // User to be removed as a follower

  try {
    const result = await pool.query(
      'DELETE FROM friends WHERE user_id = $1 AND friend_id = $2 AND status = $3',
      [followerId, userId, 'accepted']
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Follower not found' });
    }
    res.status(200).json({ message: 'Successfully removed follower' });
  } catch (err) {
    console.error('Error removing follower:', err);
    res.status(500).json({ message: 'Error removing follower' });
  }
});

// ... All your original code above remains unchanged ...

// ➕ Profile Feature Start: Routes for user profiles

// Get all user profiles (public data only)

app.get('/profiles', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT user_id, username, email, profile_pic, bio, created_at FROM users;'
    );
    res.json(result.rows); // Return JSON instead of rendering EJS
  } catch (err) {
    console.error("Error fetching user profiles:", err);
    res.status(500).json({ message: "Failed to fetch profiles" });
  }
});

// Get a single user profile by user_id
app.get('/profiles/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      'SELECT user_id, username, email, profile_pic, bio, created_at FROM users WHERE user_id = $1;',
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Profile not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

// Updated /profiles/update endpoint to handle file upload
app.put('/profiles/update', isAuthenticated, upload.single('profile_pic'), async (req, res) => {
  const userId = req.session.userId;
  const { username, bio } = req.body;
  const profilePicPath = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    const currentProfile = await pool.query(
      'SELECT profile_pic FROM users WHERE user_id = $1;',
      [userId]
    );
    const existingPic = currentProfile.rows[0].profile_pic;

    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    if (username) {
      updateFields.push(`username = $${paramCount++}`);
      updateValues.push(username);
    }
    if (bio !== undefined) {
      updateFields.push(`bio = $${paramCount++}`);
      updateValues.push(bio);
    }
    if (profilePicPath) {
      updateFields.push(`profile_pic = $${paramCount++}`);
      updateValues.push(profilePicPath);
    }

    updateFields.push(`updated_at = NOW()`);

    if (updateFields.length > 1) {
      const query = `UPDATE users SET ${updateFields.join(', ')} WHERE user_id = $${paramCount};`;
      updateValues.push(userId);

      await pool.query(query, updateValues);
      res.status(200).json({
        message: "Profile updated successfully",
        profile_pic: profilePicPath || existingPic
      });
    } else {
      res.status(400).json({ message: "No changes provided" });
    }
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});


// ➕ Profile Feature End

// ... You can continue with any additional routes after this

//likes and comments

app.get("/ratings/:ratingId/comments", async (req, res) => {
  const { ratingId } = req.params;
  const comments = await pool.query(
    `SELECT c.comment_id, c.comment, c.created_at, u.username, u.profile_pic
     FROM comments c
     JOIN users u ON u.user_id = c.user_id
     WHERE c.rating_id = $1
     ORDER BY c.created_at ASC`,
    [ratingId]
  );
  res.json(comments.rows);
});

// POST /ratings/:ratingId/comments
app.post("/ratings/:ratingId/comments", async (req, res) => {
  const { ratingId } = req.params;
  const { comment } = req.body;
  const userId = req.session.userId;

  const result = await pool.query(
    `INSERT INTO comments (user_id, rating_id, comment)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [userId, ratingId, comment]
  );
  res.json(result.rows[0]);
});

// GET /ratings/:ratingId/likes
app.get("/ratings/:ratingId/likes", async (req, res) => {
  const { ratingId } = req.params;
  const result = await pool.query(
    `SELECT COUNT(*) FROM review_likes WHERE rating_id = $1`,
    [ratingId]
  );
  res.json({ likeCount: parseInt(result.rows[0].count) });
});

// POST /ratings/:ratingId/like
app.post("/ratings/:ratingId/like", async (req, res) => {
  const { ratingId } = req.params;
  const userId = req.session.userId;

  const existing = await pool.query(
    `SELECT * FROM review_likes WHERE user_id = $1 AND rating_id = $2`,
    [userId, ratingId]
  );

  if (existing.rows.length > 0) {
    await pool.query(
      `DELETE FROM review_likes WHERE user_id = $1 AND rating_id = $2`,
      [userId, ratingId]
    );
    return res.json({ liked: false });
  } else {
    await pool.query(
      `INSERT INTO review_likes (user_id, rating_id) VALUES ($1, $2)`,
      [userId, ratingId]
    );
    return res.json({ liked: true });
  }
});


////////////////////////////////////////////////////

//narendar

app.get("/item/:itemId/status", async (req, res) => {
  if (!req.session.userId) return res.sendStatus(401);
  const { itemId } = req.params;
  const userId = req.session.userId;

  const result = await pool.query(
    "SELECT status FROM user_item_status WHERE user_id = $1 AND item_id = $2",
    [userId, itemId]
  );
  res.json(result.rows[0] || {});
});
app.post("/item/:itemId/status", async (req, res) => {
  if (!req.session.userId) return res.sendStatus(401);
  const { itemId } = req.params;
  const { status } = req.body;
  const userId = req.session.userId;

  await pool.query(`
    INSERT INTO user_item_status (user_id, item_id, status)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, item_id)
    DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
  `, [userId, itemId, status]);

  res.json({ success: true });
});

app.get('/profiles/my-items', async (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const result = await pool.query(`
      SELECT i.item_id, i.name, i.image_url, 
             COALESCE(AVG(r.rating), 0)::FLOAT AS average_rating,
             s.status
      FROM Items i
      JOIN ratings r ON i.item_id = r.item_id AND r.user_id = $1
      LEFT JOIN item_status s ON s.item_id = i.item_id AND s.user_id = $1
      GROUP BY i.item_id, s.status
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching my items:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
// Get all items with status for the logged-in user
app.get('/my-status-items', async (req, res) => {
  try {
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const result = await pool.query(`
      SELECT s.status, i.*, c.name as category_name
      FROM status s
      JOIN items i ON s.item_id = i.item_id
      JOIN categories c ON i.category_id = c.category_id
      WHERE s.user_id = $1
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching status items:', err);
    res.status(500).json({ message: 'Server error' });
  }
});



/////////////////////
// ✅ BACKEND ENDPOINT FOR USER'S ITEMS WITH STATUS

// Add this in your server.js or routes file
// app.get('/user/status-items', async (req, res) => {
//   try {
//     const userId = req.session.userId;
//     const { category_id } = req.query;
//     if (!userId) return res.status(401).json({ message: 'Unauthorized' });

//     let query = `
//       SELECT us.status, i.item_id, i.title, i.image_url, i.genre, i.release_year, c.name AS category_name
//       FROM user_item_status us
//       JOIN items i ON us.item_id = i.item_id
//       JOIN categories c ON i.category_id = c.category_id
//       WHERE us.user_id = $1
//     `;
//     const params = [userId];

//     if (category_id) {
//       query += ` AND i.category_id = $2`;
//       params.push(category_id);
//     }

//     const result = await pool.query(query, params);

//     const itemsByStatus = {};
//     result.rows.forEach(row => {
//       if (!itemsByStatus[row.status]) {
//         itemsByStatus[row.status] = [];
//       }
//       itemsByStatus[row.status].push(row);
//     });

//     res.json(itemsByStatus);
//   } catch (err) {
//     console.error('Error fetching status items:', err);
//     res.status(500).json({ message: 'Failed to fetch status items' });
//   }
// });
////Rohit

app.get('/user/status-items', async (req, res) => {
  try {
    const userId = req.session.userId;
    const { category_id } = req.query;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    let query = `
      SELECT us.status, i.item_id, i.title, i.image_url, i.genre, i.release_year, c.name AS category_name
      FROM user_item_status us
      JOIN items i ON us.item_id = i.item_id
      JOIN categories c ON i.category_id = c.category_id
      WHERE us.user_id = $1 AND us.status IS NOT NULL AND TRIM(us.status) != ''
    `;
    const params = [userId];

    if (category_id) {
      query += ` AND i.category_id = $2`;
      params.push(category_id);
    }

    const result = await pool.query(query, params);

    const itemsByStatus = {};
    result.rows.forEach(row => {
      if (!itemsByStatus[row.status]) {
        itemsByStatus[row.status] = [];
      }
      itemsByStatus[row.status].push(row);
    });

    // Log the response for debugging
    console.log('Items by status:', itemsByStatus);
    res.json(itemsByStatus);
  } catch (err) {
    console.error('Error fetching status items:', err);
    res.status(500).json({ message: 'Failed to fetch status items' });
  }
});

// Get notifications for comments on user's reviews
app.get('/notifications/comments', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }

  try {
    const result = await pool.query(
      `SELECT 
         c.comment_id, 
         c.comment, 
         c.rating_id, 
         u.username, 
         u.profile_pic, 
         i.item_id, 
         i.title AS item_title
       FROM Comments c
       JOIN Ratings r ON c.rating_id = r.rating_id
       JOIN Users u ON c.user_id = u.user_id
       JOIN Items i ON r.item_id = i.item_id
       WHERE r.user_id = $1 AND c.is_read = FALSE
       LIMIT 10`,
      [req.session.userId]
    );
    console.log('Comment notifications fetched:', result.rows);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching comment notifications:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/notifications/comments/clear', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    await pool.query(
      `UPDATE Comments c
       SET is_read = TRUE
       WHERE c.rating_id IN (
         SELECT r.rating_id FROM Ratings r WHERE r.user_id = $1
       )`,
      [userId]
    );
    res.status(200).json({ message: 'Comment notifications cleared' });
  } catch (error) {
    console.error('Error clearing comment notifications:', error);
    res.status(500).json({ message: 'Failed to clear notifications' });
  }
});

// Get followers (users who follow the logged-in user)
app.get('/followers', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }
  try {
    const result = await pool.query(
      'SELECT u.user_id, u.username, u.profile_pic ' +
      'FROM Friends f ' +
      'JOIN Users u ON f.user_id = u.user_id ' +
      'WHERE f.friend_id = $1 AND f.status = $2',
      [req.session.userId, 'accepted']
    );
    console.log('Followers:', result.rows); // Debug log
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching followers:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get following (users the logged-in user follows)
app.get('/following', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }
  try {
    const result = await pool.query(
      'SELECT u.user_id, u.username, u.profile_pic ' +
      'FROM Friends f ' +
      'JOIN Users u ON f.friend_id = u.user_id ' +
      'WHERE f.user_id = $1 AND f.status = $2',
      [req.session.userId, 'accepted']
    );
    console.log('Following:', result.rows); // Debug log
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching following:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get user details (for profile header)
app.get('/users/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT user_id, username, bio, profile_pic FROM Users WHERE user_id = $1',
      [req.params.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching user:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get user's reviews
app.get('/users/:userId/reviews', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         r.rating_id, 
         r.rating, 
         r.review, 
         i.item_id, 
         i.title AS item_title, 
         i.image_url AS item_image,
         (SELECT json_agg(
            json_build_object(
              'comment_id', c.comment_id,
              'user_id', c.user_id,
              'username', u.username,
              'comment', c.comment
            )
          ) FROM Comments c
          JOIN Users u ON c.user_id = u.user_id
          WHERE c.rating_id = r.rating_id) AS comments
       FROM Ratings r
       JOIN Items i ON r.item_id = i.item_id
       WHERE r.user_id = $1`,
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching user reviews:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Add a comment to a review
app.post('/reviews/:ratingId/comments', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Not logged in' });
  }
  const { comment_text } = req.body;
  if (!comment_text) {
    return res.status(400).json({ message: 'Comment text is required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO Comments (rating_id, user_id, comment) 
       VALUES ($1, $2, $3) 
       RETURNING comment_id, user_id, (SELECT username FROM Users WHERE user_id = $2) AS username`,
      [req.params.ratingId, req.session.userId, comment_text]
    );
    const newComment = {
      comment_id: result.rows[0].comment_id,
      user_id: result.rows[0].user_id,
      username: result.rows[0].username,
      comment: comment_text,
    };
    res.json({ message: 'Comment added', comment: newComment });
  } catch (err) {
    console.error('Error adding comment:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message});
  }
});

// app.get('/search', async (req, res) => {
//   const { query } = req.query;
//   try {
//     const result = await pool.query(
//       `SELECT item_id, title FROM items WHERE LOWER(title) LIKE LOWER($1) LIMIT 10`,
//       [`%${query}%`]
//     );
//     res.json(result.rows);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Search failed"});
//   }
// });

// Backend (Node.js)
app.get('/search', async (req, res) => {
  const { query, detailed } = req.query; // Add 'detailed' flag
  try {
    let result;
    if (detailed === 'true') {
      // Return detailed results with image_url and release_year
      result = await pool.query(
        `SELECT item_id, title, image_url, release_year 
         FROM Items 
         WHERE LOWER(title) LIKE LOWER($1)`,
        [`%${query}%`]
      );
    } else {
      // Return basic results for suggestions
      result = await pool.query(
        `SELECT item_id, title 
         FROM Items 
         WHERE LOWER(title) LIKE LOWER($1) 
         LIMIT 10`,
        [`%${query}%`]
      );
    }
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Search failed" });
  }
});
// Start the server

//chat fro friends

// In server.js

app.get('/api/user/get-followers', async (req, res) => {
  try {
    const userId = req.session.user.user_id;

    const result = await pool.query(
      `SELECT u.user_id, u.username
       FROM users u
       JOIN friends f ON f.user_id = u.user_id
       WHERE f.friend_id = $1 AND f.status = 'accepted'`,
      [userId]
    );

    res.json({ followers: result.rows });
  } catch (error) {
    console.error('Error fetching followers:', error);
    res.status(500).json({ message: 'Error fetching followers' });
  }
});

app.get('/api/user/get-following', async (req, res) => {
  try {
    const userId = req.session.user.user_id;

    const result = await pool.query(
      `SELECT u.user_id, u.username
       FROM users u
       JOIN friends f ON f.friend_id = u.user_id
       WHERE f.user_id = $1 AND f.status = 'accepted'`,
      [userId]
    );

    res.json({ following: result.rows });
  } catch (error) {
    console.error('Error fetching following:', error);
    res.status(500).json({ message: 'Error fetching following' });
  }
});


//char real

// POST: Send a message
app.post("/chat", async (req, res) => {
  const sender_id = req.session.userId;
  const { receiver_id, message } = req.body;

  if (!sender_id || !receiver_id || !message) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3) RETURNING *",
      [sender_id, receiver_id, message]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error sending message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET: Fetch chat messages between current user and receiver
app.get("/chat/:receiverId", async (req, res) => {
  const userId = req.session.userId;
  const { receiverId } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM messages
       WHERE (sender_id = $1 AND receiver_id = $2)
          OR (sender_id = $2 AND receiver_id = $1)
       ORDER BY timestamp`,
      [userId, receiverId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching chat:", err);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});
app.get('/current-user', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  res.json({ userId: req.session.userId });
});

// server.js
app.get("/friends", isAuthenticated, async (req, res) => {
  const userId = req.session.userId;

  const query = `
    SELECT 
     DISTINCT ON (u.user_id)
      u.user_id,
      u.username,
      u.profile_pic,
      u.bio,
  (
    SELECT COUNT(*) FROM messages
    WHERE sender_id = u.user_id AND receiver_id = $1 AND is_read = false
      AND NOT $1 = ANY(deleted_for)
  ) AS unreadcount
FROM users u
JOIN friends f ON (
    (f.user_id = $1 AND f.friend_id = u.user_id) OR
    (f.friend_id = $1 AND f.user_id = u.user_id)
)
WHERE f.status = 'accepted' AND u.user_id != $1;

  `;

  try {
    const result = await pool.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching friends:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.post('/chat/:friendId/read', isAuthenticated, async (req, res) => {
  const { friendId } = req.params;
  const userId = req.session.userId;

  try {
    await pool.query(`
      UPDATE messages
      SET is_read = true
      WHERE sender_id = $1 AND receiver_id = $2
    `, [friendId, userId]);

    res.sendStatus(200);
  } catch (err) {
    console.error("Error marking messages as read:", err);
    res.status(500).json({ error: "Failed to mark messages as read" });
  }
});
// DELETE message by ID
app.delete('/chat/:messageId', async (req, res) => {
  const { messageId } = req.params;
  const userId = req.session.userId;

  try {
    const result = await pool.query(`
      UPDATE messages
      SET deleted_for = array_append(deleted_for, $1)
      WHERE message_id = $2 AND NOT $1 = ANY(deleted_for)
      RETURNING *
    `, [userId, messageId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Message not found or already deleted" });
    }

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error marking message as deleted:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get('/chat/:otherUserId', async (req, res) => {
  const userId = req.session.userId;
  const otherUserId = req.params.otherUserId;

  try {
    const result = await pool.query(`
      SELECT m.*, u.username
      FROM messages m
      JOIN users u ON u.user_id = m.sender_id
      WHERE (
          (m.sender_id = $1 AND m.receiver_id = $2)
          OR (m.sender_id = $2 AND m.receiver_id = $1)
        )
        AND NOT $1 = ANY(m.deleted_for)
      ORDER BY m.timestamp
    `, [userId, otherUserId]);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post('/notifications/comments/clear', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId; // Get user ID from session
    // Delete comments on the user's ratings
    await pool.query(
      `DELETE FROM Comments c
       WHERE c.rating_id IN (
         SELECT r.rating_id FROM Ratings r WHERE r.user_id = $1
       )`,
      [userId]
    );
    res.status(200).json({ message: 'Comment notifications cleared' });
  } catch (error) {
    console.error('Error clearing comment notifications:', error);
    res.status(500).json({ message: 'Failed to clear notifications' });
  }
});


//recommendations

// In your backend server.js or routes file

// Get genres for a specific category
app.get('/category/:categoryId/genres', async (req, res) => {
  const { categoryId } = req.params;
  try {
    const result = await pool.query(
      `SELECT DISTINCT genre FROM items WHERE category_id = $1 AND genre IS NOT NULL`,
      [categoryId]
    );
    res.json(result.rows.map(row => row.genre));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Save favorite genre
app.put('/user/:userId/favorite-genre', async (req, res) => {
  const { userId } = req.params;
  const { categoryId, genre } = req.body;
  try {
    await pool.query(
      `INSERT INTO user_favorite_genres (user_id, category_id, genre)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, category_id) 
       DO UPDATE SET genre = EXCLUDED.genre`,
      [userId, categoryId, genre]
    );
    res.json({ message: 'Favorite genre saved successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's favorite genres
app.get('/user/:userId/favorite-genres', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT ufg.category_id, c.name as category_name, ufg.genre
       FROM user_favorite_genres ufg
       JOIN categories c ON c.category_id = ufg.category_id
       WHERE ufg.user_id = $1`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});
 
// In your backend server.js
app.delete('/user/:userId/favorite-genre/:categoryId', async (req, res) => {
  const { userId, categoryId } = req.params;
  try {
    await pool.query(
      'DELETE FROM user_favorite_genres WHERE user_id = $1 AND category_id = $2',
      [userId, categoryId]
    );
    res.json({ message: 'Favorite genre deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// In your backend server.js
// In your backend server.js

// // First, add this route to check what genres are saved
// app.get('/api/recommendations/:userId', async (req, res) => {
//   const { userId } = req.params;
//   try {
//     const result = await pool.query(`
//       SELECT i.*
//       FROM items i
//       JOIN user_favorite_genres ufg
//         ON i.category_id = ufg.category_id AND i.genre = ufg.genre
//       WHERE ufg.user_id = $1
//     `, [userId]);

//     res.json(result.rows);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Failed to fetch recommendations' });
//   }
// });

// In your server.js
app.get('/api/recommendations', async (req, res) => {
  try {
    const userId = req.session.userId;
    if (!userId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const query = `
      SELECT 
        i.item_id,
        i.title,
        i.image_url,
        i.genre,
        i.category_id,
        c.name as category_name,
        COALESCE(AVG(r.rating), 0) as average_rating
      FROM user_favorite_genres ufg
      JOIN categories c ON ufg.category_id = c.category_id
      JOIN items i ON i.category_id = ufg.category_id 
        AND i.genre = ufg.genre
      LEFT JOIN ratings r ON i.item_id = r.item_id
      WHERE ufg.user_id = $1
      GROUP BY 
        i.item_id,
        i.title,
        i.image_url,
        i.genre,
        i.category_id,
        c.name
      ORDER BY c.name, i.title;
    `;

    const result = await pool.query(query, [userId]);
    console.log('Query results:', result.rows); // Debug log

    // Group by category
    const recommendations = result.rows.reduce((acc, item) => {
      if (!acc[item.category_id]) {
        acc[item.category_id] = {
          category_name: item.category_name,
          items: []
        };
      }
      acc[item.category_id].items.push({
        item_id: item.item_id,
        title: item.title,
        image_url: item.image_url,
        genre: item.genre,
        average_rating: Number(item.average_rating).toFixed(1)
      });
      return acc;
    }, {});

    res.json({ recommendations });
  } catch (err) {
    console.error('Error fetching recommendations:', err);
    res.status(500).json({ error: 'Failed to fetch recommendations' });
  }
});


///count of reviews and ratings

// In your server.js
app.get('/api/user/stats', async (req, res) => {
  try {
    const userId = req.session.userId;
    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const query = `
      SELECT 
        COUNT(DISTINCT CASE WHEN rating IS NOT NULL THEN rating_id END) as rating_count,
        COUNT(DISTINCT CASE WHEN review IS NOT NULL AND review != '' THEN rating_id END) as review_count
      FROM ratings 
      WHERE user_id = $1
    `;

    const result = await pool.query(query, [userId]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching user stats:', err);
    res.status(500).json({ error: 'Failed to fetch user statistics' });
  }
});
// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});


