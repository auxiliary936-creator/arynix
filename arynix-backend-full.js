const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const nodemailer = require('nodemailer');
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// ============ DATABASE SETUP ============
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/arynix', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  fullName: String,
  avatar: String,
  plan: { type: String, enum: ['free', 'pro', 'enterprise'], default: 'free' },
  messagesUsed: { type: Number, default: 0 },
  messagesLimit: { type: Number, default: 100 },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  isVerified: { type: Boolean, default: false },
  verificationToken: String
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Conversation Schema
const ConversationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: String,
  messages: [{
    role: { type: String, enum: ['user', 'assistant'] },
    content: String,
    timestamp: { type: Date, default: Date.now },
    tokensUsed: Number
  }],
  totalTokens: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Analytics Schema
const AnalyticsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  eventType: String,
  metadata: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
  ipAddress: String,
  userAgent: String
});

const User = mongoose.model('User', UserSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);

// ============ EMAIL SETUP ============
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// ============ MIDDLEWARE ============
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb' }));

const corsOptions = {
  origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'https://arynix.com', 'www.arynix.com'],
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});
app.use('/api/', limiter);

// File upload
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'];
    cb(allowed.includes(file.mimetype) ? null : new Error('Invalid file'), allowed.includes(file.mimetype));
  }
});

// JWT Strategy
passport.use(new JwtStrategy({
  jwtFromRequest: req => req.cookies?.token || req.headers?.authorization?.split(' ')[1],
  secretOrKey: process.env.JWT_SECRET || 'arynix-secret-key'
}, async (payload, done) => {
  try {
    const user = await User.findById(payload.id);
    return user ? done(null, user) : done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

app.use(passport.initialize());

// Middleware: Track analytics
async function trackEvent(req, res, next) {
  res.on('finish', async () => {
    try {
      if (req.user?._id) {
        await Analytics.create({
          userId: req.user._id,
          eventType: `${req.method} ${req.path}`,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          metadata: { status: res.statusCode }
        });
      }
    } catch (err) {
      console.error('Analytics error:', err);
    }
  });
  next();
}
app.use(trackEvent);

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    if (await User.findOne({ $or: [{ username }, { email }] })) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET || 'arynix-secret-key', { expiresIn: '24h' });
    const user = await User.create({
      username,
      email,
      password,
      fullName,
      verificationToken,
      messagesLimit: 100
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'arynix-secret-key', { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });

    res.json({ success: true, user: { id: user._id, username, email }, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'arynix-secret-key', { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });

    res.json({ success: true, user: { id: user._id, username: user.username, email }, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ============ USER ROUTES ============

app.get('/api/user/profile', passport.authenticate('jwt', { session: false }), async (req, res) => {
  res.json(req.user);
});

app.put('/api/user/profile', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const { fullName, avatar } = req.body;
    await User.findByIdAndUpdate(req.user._id, { fullName, avatar });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/user/usage', passport.authenticate('jwt', { session: false }), async (req, res) => {
  res.json({
    messagesUsed: req.user.messagesUsed,
    messagesLimit: req.user.messagesLimit,
    plan: req.user.plan,
    percentageUsed: Math.round((req.user.messagesUsed / req.user.messagesLimit) * 100)
  });
});

// ============ CHAT ROUTES ============

app.post('/api/chat', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const { message, conversationId, stream = false } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message required' });
    }

    // Check message limit
    if (req.user.messagesUsed >= req.user.messagesLimit) {
      return res.status(429).json({ error: 'Message limit exceeded. Upgrade plan.' });
    }

    let conversation = conversationId ? 
      await Conversation.findById(conversationId) : 
      new Conversation({ userId: req.user._id, title: message.substring(0, 50) });

    conversation.messages.push({ role: 'user', content: message });
    const messages = conversation.messages.map(m => ({ role: m.role, content: m.content }));

    const SYSTEM_PROMPT = `You are Arynix, space knowledge AI. Help with spaceflight, astronomy, Mars, rocketry, exoplanets. Be helpful, accurate, and inspiring.`;

    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: process.env.OPENAI_MODEL || 'gpt-3.5-turbo',
      messages: [{ role: 'system', content: SYSTEM_PROMPT }, ...messages],
      max_tokens: 1500,
      temperature: 0.7
    }, {
      headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` }
    });

    const assistantMessage = response.data.choices[0].message.content;
    const tokensUsed = response.data.usage.total_tokens;

    conversation.messages.push({ role: 'assistant', content: assistantMessage, tokensUsed });
    conversation.totalTokens += tokensUsed;
    conversation.updatedAt = new Date();
    await conversation.save();

    // Update user usage
    req.user.messagesUsed += 1;
    await req.user.save();

    res.json({ success: true, message: assistantMessage, conversationId: conversation._id, tokensUsed });
  } catch (error) {
    console.error('Chat error:', error.response?.data || error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/conversations', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const conversations = await Conversation.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json(conversations);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/conversations/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const conversation = await Conversation.findOne({ _id: req.params.id, userId: req.user._id });
    if (!conversation) return res.status(404).json({ error: 'Not found' });
    res.json(conversation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/conversations/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    await Conversation.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ FILE UPLOAD ============

app.post('/api/upload', passport.authenticate('jwt', { session: false }), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });

    const fileContent = fs.readFileSync(req.file.path, 'utf8');
    const { conversationId, query } = req.body;

    let conversation = conversationId ? 
      await Conversation.findById(conversationId) : 
      new Conversation({ userId: req.user._id, title: req.file.originalname });

    const userMessage = `Analyze: ${req.file.originalname}\n${fileContent}\n\nQuery: ${query || 'Summarize'}`;
    conversation.messages.push({ role: 'user', content: userMessage });

    const messages = conversation.messages.map(m => ({ role: m.role, content: m.content }));

    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: process.env.OPENAI_MODEL || 'gpt-3.5-turbo',
      messages,
      max_tokens: 2000
    }, {
      headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` }
    });

    const assistantMessage = response.data.choices[0].message.content;
    conversation.messages.push({ role: 'assistant', content: assistantMessage });
    await conversation.save();

    fs.unlinkSync(req.file.path);

    res.json({ success: true, analysis: assistantMessage, conversationId: conversation._id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ANALYTICS ============

app.get('/api/analytics/dashboard', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const userId = req.user._id;

    const totalMessages = await Conversation.aggregate([
      { $match: { userId } },
      { $group: { _id: null, count: { $sum: { $size: '$messages' } } } }
    ]);

    const totalConversations = await Conversation.countDocuments({ userId });

    const lastWeekMessages = await Analytics.countDocuments({
      userId,
      eventType: 'message',
      timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });

    const topFeatures = await Analytics.aggregate([
      { $match: { userId } },
      { $group: { _id: '$eventType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    res.json({
      totalMessages: totalMessages[0]?.count || 0,
      totalConversations,
      lastWeekMessages,
      topFeatures,
      plan: req.user.plan,
      messagesUsed: req.user.messagesUsed,
      messagesLimit: req.user.messagesLimit
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ HEALTH CHECK ============

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// ============ ERROR HANDLING ============

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// ============ START SERVER ============

app.listen(PORT, () => {
  console.log(`🚀 Arynix backend running on port ${PORT}`);
  console.log(`📡 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
  console.log(`🔐 Auth enabled`);
});
