const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = 5000;
const JWT_SECRET = "G346278i4";

// Connect to the MySQL database
const db = mysql.createConnection({
    host: "localhost",
    user: "root",       // MySQL username
    password: "Temp@2019",       // MySQL password
    database: "tenant_database"
});

db.connect((err) => {
    if (err) {
        console.error("Database connection error:", err);
    } else {
        console.log("Connected to TENANT-DATABASE");
    }
});

// API endpoint for user registration (for adding new users)
app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;
    try {
        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        db.query(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword],
            (err, results) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(400).json({ error: "Username already exists" });
                    }
                    return res.status(500).json({ error: "Database error" });
                }
                res.json({ message: "User registered successfully" });
            }
        );
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});

// API endpoint for user login
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        // Retrieve user from the database
        db.query(
            "SELECT * FROM users WHERE username = ?",
            [username],
            async (err, results) => {
                if (err) return res.status(500).json({ error: "Database error" });

                // Check if user exists
                if (results.length === 0) {
                    return res.status(400).json({ error: "User not found" });
                }

                const user = results[0];

                // Check if password is correct
                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (!isPasswordValid) {
                    return res.status(400).json({ error: "Invalid password" });
                }

                // Create JWT Token
                const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
                res.json({ message: "Login successful", token });
            }
        );
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${5000}`));
