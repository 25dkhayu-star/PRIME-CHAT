const express = require('express');
const { Server } = require('ws');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;
const secret = 'your_jwt_secret'; // Replace with a secure secret in production

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Content Security Policy
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; connect-src 'self' ws://localhost:3000; style-src 'self' https://cdnjs.cloudflare.com; img-src 'self';"
  );
  next();
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/primechat', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  friends: [{ userId: String, username: String }]
});
const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  senderId: String,
  receiverId: String,
  message: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// Middleware to verify JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, secret);
    req.user = await User.findById(decoded.userId);
    if (!req.user) return res.status(401).json({ message: 'User not found' });
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Register Endpoint
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already taken' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ userId: user._id }, secret, { expiresIn: '1h' });
    res.json({ user: { _id: user._id, username, email }, token });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, secret, { expiresIn: '1h' });
    res.json({ user: { _id: user._id, username: user.username, email }, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify Token Endpoint
app.get('/verify', authenticate, (req, res) => {
  res.json({ user: { _id: req.user._id, username: req.user.username, email: req.user.email } });
});

// Add Friend Endpoint
app.post('/friends', authenticate, async (req, res) => {
  const { friendUsername } = req.body;
  try {
    const friend = await User.findOne({ username: friendUsername });
    if (!friend) return res.status(404).json({ message: 'User not found' });
    if (friend._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot add yourself as a friend' });
    }
    if (req.user.friends.some(f => f.userId === friend._id.toString())) {
      return res.status(400).json({ message: 'Friend already added' });
    }
    req.user.friends.push({ userId: friend._id, username: friend.username });
    await req.user.save();
    res.json({ message: 'Friend added' });
  } catch (error) {
    console.error('Add friend error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Friends Endpoint
app.get('/friends', authenticate, async (req, res) => {
  res.json(req.user.friends);
});

// Get Messages Endpoint
app.get('/messages/:friendId', authenticate, async (req, res) => {
  const { friendId } = req.params;
  try {
    const messages = await Message.find({
      $or: [
        { senderId: req.user._id, receiverId: friendId },
        { senderId: friendId, receiverId: req.user._id }
      ]
    }).sort({ timestamp: 1 });
    const messagesWithSender = await Promise.all(messages.map(async msg => {
      const sender = await User.findById(msg.senderId);
      return {
        senderId: msg.senderId,
        senderUsername: sender ? sender.username : 'Unknown',
        message: msg.message,
        timestamp: msg.timestamp
      };
    }));
    res.json(messagesWithSender);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// WebSocket Server
const server = app.listen(port, () => console.log(`Server running on port ${port}`));
const wss = new Server({ server });

const clients = new Map();

wss.on('connection', (ws) => {
  ws.on('message', async (message) => {
    const data = JSON.parse(message);
    if (data.type === 'auth') {
      try {
        const decoded = jwt.verify(data.token, secret);
        const user = await User.findById(decoded.userId);
        if (user) {
          clients.set(user._id.toString(), ws);
          ws.userId = user._id.toString();
        } else {
          ws.close();
        }
      } catch (error) {
        ws.close();
      }
    } else if (data.type === 'message' && ws.userId) {
      const { friendId, message } = data;
      const msg = new Message({
        senderId: ws.userId,
        receiverId: friendId,
        message
      });
      await msg.save();
      const sender = await User.findById(ws.userId);
      const messageData = {
        type: 'message',
        senderId: ws.userId,
        senderUsername: sender.username,
        friendId,
        message
      };
      // Send to sender
      if (clients.get(ws.userId)) {
        clients.get(ws.userId).send(JSON.stringify(messageData));
      }
      // Send to receiver
      if (clients.get(friendId)) {
        clients.get(friendId).send(JSON.stringify(messageData));
      }
    }
  });

  ws.on('close', () => {
    if (ws.userId) clients.delete(ws.userId);
  });
});