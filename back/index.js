import express from 'express';
import cors from 'cors';
// FIX 1: Converted require() to import. MUST include the .js extension for local files in ESM.
import connectDB from './db/connect.js'; 
import 'dotenv/config.js';
// FIX 2: Converted require() to import. MUST include the .js extension for local files in ESM.
// Note: This assumes './models/UserModel.js' uses 'export default' for the array or model.
import User from './models/UserModel.js';
// encrypt password
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 5000;
const SECRET = 'mishpat_sodi';

app.use(cors());
app.use(express.json());

//create new user
// POST /register

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Missing username or password' });
    }

    // 2. Encryption (The Professional Step)
    // We strictly NEVER save the 'password' variable directly.
    // We run it through bcrypt with 10 salt rounds.
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Database Insertion
    // Notice: We pass 'hashedPassword' into the password field.
    const user = await User.create({
      username,
      password: hashedPassword, 
    });

    console.log(`User created (Secured): ${user.username}`);
    
    // 4. Response
    // We return the user ID, but we do NOT return the password (even the hash).
    res.status(201).json({ 
        message: "User registered successfully", 
        userId: user._id 
    });

  } catch (error) {
    // Handle "Username already exists" error
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Username already taken' });
    }
    res.status(500).json({ message: error.message });
  }
});
  

// THE LOGIN PHASE (Secure Authentication)
// -----------------------------------------------------------------------------
app.post('/login', async (req, res) => {
  // 1. INPUT: Extract data from the client
  const { username, password } = req.body;

  try {
    // 2. SEARCH: Find the user by Username ONLY
    // We strictly use findOne() because we need the specific document to get the hash.
    // We do NOT search by password here.
    const user = await User.findOne({ username });
  
    // 3. GUARD 1: User Existence Check
    // If the user doesn't exist, stop immediately.
    // Pro Tip: Use generic messages ("Invalid credentials") to prevent user enumeration attacks.
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 4. VERIFY: The Cryptographic Comparison
    // This is the most critical line. We compare the plain text input vs the DB hash.
    // await bcrypt.compare(plainText, hash) -> Returns Boolean
    const isMatch = await bcrypt.compare(password, user.password);

    // 5. GUARD 2: Password Check
    // If the math doesn't add up, the password is wrong. Stop.
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 6. ISSUE: Generate the Access Token (JWT)
    // Only reachable if both Guards passed.
    const token = jwt.sign(
      { 
        id: user._id,           // The MongoDB ID (used for database lookups later)
        username: user.username // Helpful data for the frontend to display
      }, 
      SECRET, 
      { expiresIn: '1h' }       // Security best practice: expire tokens quickly
    );

    // 7. SUCCESS: Send the token to the client
    console.log(`Login successful: ${username}`);
    res.json({ token });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Middleware to verify token for protected routes (optional, but good practice)
// function verifyToken(req, res, next) { ... }

app.get('/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ message: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    // You would typically attach the decoded user to the request object here: req.user = decoded;
    res.json({ message: `Welcome ${decoded.username}! This is protected data.` });
  } catch (err) {
    // Log the actual error for debugging, but send generic 403 to client
    console.error("JWT Verification Error:", err.message);
    res.status(403).json({ message: 'Invalid or expired token' });
  }
});

const start = async () => {
  try {
    // Ensure that your connectDB function can handle being imported as an ESM module.
    await connectDB(process.env.MONGO_URI);
    
    app.listen(PORT, () =>
      console.log(`Masad netunim connected. Server is listening on port ${PORT} 🛜...`));
  } catch (error) {
    console.log(error);
    // A professional setup would typically exit the process on database connection failure
    // process.exit(1);
  }
};

start();