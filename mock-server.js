/**
 * LOCAL TEST MOCK SERVER
 * Simulates the VPS manager API so you can test the panel UI locally.
 * Run: node mock-server.js
 * This does NOT deploy real bots — it's for UI testing only.
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const app     = express();
app.use(express.json());

const PORT    = 3001;
const API_KEY = 'test-key';
const ADMIN_PW = 'admin123';

// In-memory store
const users          = new Map(); // id -> user
const deployments    = new Map(); // botId -> deployment
const transactions   = [];
const paymentRequests = new Map(); // id -> request
let nextPrId = 1;
let nextId = 1;

const requireApiKey = (req, res, next) => {
  if (req.headers['x-api-key'] !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
};
const requireAdmin = (req, res, next) => {
  if (req.headers['x-admin-key'] !== ADMIN_PW) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// Register
app.post('/register', requireApiKey, async (req, res) => {
  const { username, email, name, password } = req.body;
  if (!username || !email || !name || !password)
    return res.status(400).json({ error: 'All fields are required.' });
  if (!/^[a-z0-9_]{3,30}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3-30 chars: lowercase, numbers, underscores only.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  for (const u of users.values()) {
    if (u.username === username) return res.status(409).json({ error: 'Username already taken.' });
    if (u.email === email) return res.status(409).json({ error: 'Email already registered.' });
  }

  const password_hash = await bcrypt.hash(password, 10);
  const user = { id: nextId++, username, email, name, password_hash, coins: 0, created_at: new Date().toISOString() };
  users.set(user.id, user);
  res.json({ success: true, user: { id: user.id, username, email, name, coins: 0 } });
});

// Login
app.post('/login', requireApiKey, async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'Username/email and password are required.' });

  let found = null;
  for (const u of users.values()) {
    if (u.username === login || u.email === login) { found = u; break; }
  }
  if (!found) return res.status(401).json({ error: 'Invalid username or password.' });
  const valid = await bcrypt.compare(password, found.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });

  res.json({ success: true, user: { id: found.id, username: found.username, email: found.email, name: found.name, coins: found.coins } });
});

// Get user
app.get('/users/:id', requireApiKey, (req, res) => {
  const user = users.get(parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const userBots = [...deployments.values()].filter(d => d.user_id === user.id);
  const activeBots = userBots.filter(d => d.status === 'running').length;
  res.json({
    id: user.id, username: user.username, email: user.email, name: user.name, coins: user.coins,
    totalBots: userBots.length, activeBots, inactiveBots: userBots.length - activeBots,
    activeDeployment: userBots.find(d => d.status === 'running') || null
  });
});

// Get deployments
app.get('/users/:id/deployments', requireApiKey, (req, res) => {
  const uid = parseInt(req.params.id);
  res.json([...deployments.values()].filter(d => d.user_id === uid).reverse());
});

// Get transactions
app.get('/users/:id/transactions', requireApiKey, (req, res) => {
  const uid = parseInt(req.params.id);
  res.json(transactions.filter(t => t.user_id === uid).slice(-20).reverse());
});

// Deploy (mock — no real PM2)
app.post('/deploy', requireApiKey, (req, res) => {
  const { userId, sessionId, appName } = req.body;
  const user = users.get(parseInt(userId));
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.coins < 1) return res.status(402).json({ error: 'Not enough coins. Contact admin to top up.' });

  const active = [...deployments.values()].find(d => d.user_id === user.id && d.status === 'running');
  if (active) return res.status(409).json({ error: 'You already have an active bot running.', botId: active.bot_id });

  const botId = 'bot-' + Date.now();
  const name  = appName || 'msb-' + user.username;
  deployments.set(botId, {
    id: deployments.size + 1, user_id: user.id, bot_id: botId, app_name: name,
    session_preview: sessionId.substring(0, 30) + '...',
    status: 'running', deployed_at: new Date().toISOString(), stopped_at: null
  });

  user.coins -= 1;
  transactions.push({ id: transactions.length + 1, user_id: user.id, amount: -1, type: 'deploy', description: 'Bot deployed: ' + name, created_at: new Date().toISOString() });
  res.json({ success: true, botId, coinsRemaining: user.coins });
});

// Stop bot
app.delete('/deploy/:botId', requireApiKey, (req, res) => {
  const dep = deployments.get(req.params.botId);
  if (!dep) return res.status(404).json({ error: 'Bot not found.' });
  dep.status = 'stopped';
  dep.stopped_at = new Date().toISOString();
  res.json({ success: true });
});

// Admin auth
app.post('/admin/auth', requireApiKey, (req, res) => {
  if (req.body.password !== ADMIN_PW) return res.status(403).json({ error: 'Invalid admin password.' });
  res.json({ success: true });
});

// Admin users list
app.get('/admin/users', requireApiKey, requireAdmin, (req, res) => {
  res.json([...users.values()].map(u => ({
    ...u,
    password_hash: undefined,
    active_bots: [...deployments.values()].filter(d => d.user_id === u.id && d.status === 'running').length
  })).reverse());
});

// Admin top-up
app.post('/admin/users/:username/topup', requireApiKey, requireAdmin, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Amount must be positive.' });
  let found = null;
  for (const u of users.values()) { if (u.username === req.params.username) { found = u; break; } }
  if (!found) return res.status(404).json({ error: 'User not found.' });
  found.coins += parseInt(amount);
  transactions.push({ id: transactions.length + 1, user_id: found.id, amount, type: 'topup', description: `Admin top-up: +${amount} coins`, created_at: new Date().toISOString() });
  res.json({ success: true, newCoins: found.coins });
});

// Admin deployments
app.get('/admin/deployments', requireApiKey, requireAdmin, (req, res) => {
  res.json([...deployments.values()].map(d => ({
    ...d, username: users.get(d.user_id)?.username, email: users.get(d.user_id)?.email
  })).reverse());
});

// Admin stop bot
app.delete('/admin/deployments/:botId', requireApiKey, requireAdmin, (req, res) => {
  const dep = deployments.get(req.params.botId);
  if (!dep) return res.status(404).json({ error: 'Bot not found.' });
  dep.status = 'stopped_by_admin';
  dep.stopped_at = new Date().toISOString();
  res.json({ success: true });
});

// Admin stats
app.get('/admin/stats', requireApiKey, requireAdmin, (req, res) => {
  const allUsers = [...users.values()];
  res.json({
    totalUsers:       allUsers.length,
    activeBots:       [...deployments.values()].filter(d => d.status === 'running').length,
    totalDeployments: deployments.size,
    totalCoins:       allUsers.reduce((s, u) => s + u.coins, 0),
    recentUsers: allUsers.slice(-10).reverse().map(u => ({
      username: u.username, email: u.email, name: u.name, coins: u.coins, created_at: u.created_at,
      active_bots: [...deployments.values()].filter(d => d.user_id === u.id && d.status === 'running').length
    }))
  });
});

// ─── Payment Requests ─────────────────────────────────────────────────────────

app.post('/payment-requests', requireApiKey, (req, res) => {
  const { userId, package: pkg, amount_usd, coins, screenshot, note } = req.body;
  if (!userId || !pkg || !amount_usd || !coins)
    return res.status(400).json({ error: 'Missing required fields.' });

  const pending = [...paymentRequests.values()].find(p => p.user_id === userId && p.status === 'pending');
  if (pending) return res.status(409).json({ error: 'You already have a pending payment request. Wait for admin to review it.' });

  const pr = { id: nextPrId++, user_id: userId, package: pkg, amount_usd, coins, screenshot: screenshot || null, note: note || null, status: 'pending', created_at: new Date().toISOString(), reviewed_at: null };
  paymentRequests.set(pr.id, pr);
  res.json({ success: true, id: pr.id });
});

app.get('/users/:id/payment-requests', requireApiKey, (req, res) => {
  const uid = parseInt(req.params.id);
  const rows = [...paymentRequests.values()].filter(p => p.user_id === uid)
    .map(p => ({ id: p.id, package: p.package, amount_usd: p.amount_usd, coins: p.coins, note: p.note, status: p.status, created_at: p.created_at, reviewed_at: p.reviewed_at }))
    .reverse().slice(0, 10);
  res.json(rows);
});

app.get('/admin/payment-requests', requireApiKey, requireAdmin, (req, res) => {
  const rows = [...paymentRequests.values()].map(p => ({
    ...p, username: users.get(p.user_id)?.username, email: users.get(p.user_id)?.email
  })).sort((a, b) => (a.status === 'pending' ? -1 : 1));
  res.json(rows);
});

app.post('/admin/payment-requests/:id/approve', requireApiKey, requireAdmin, (req, res) => {
  const pr = paymentRequests.get(parseInt(req.params.id));
  if (!pr) return res.status(404).json({ error: 'Request not found.' });
  if (pr.status !== 'pending') return res.status(400).json({ error: 'Already reviewed.' });
  pr.status = 'approved'; pr.reviewed_at = new Date().toISOString();
  const user = users.get(pr.user_id);
  if (user) {
    user.coins += pr.coins;
    transactions.push({ id: transactions.length + 1, user_id: pr.user_id, amount: pr.coins, type: 'topup', description: `Payment approved: ${pr.package} (+${pr.coins} coins)`, created_at: new Date().toISOString() });
  }
  res.json({ success: true });
});

app.post('/admin/payment-requests/:id/reject', requireApiKey, requireAdmin, (req, res) => {
  const pr = paymentRequests.get(parseInt(req.params.id));
  if (!pr) return res.status(404).json({ error: 'Request not found.' });
  if (pr.status !== 'pending') return res.status(400).json({ error: 'Already reviewed.' });
  pr.status = 'rejected'; pr.reviewed_at = new Date().toISOString();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`\n✅ Mock VPS server running on port ${PORT}`);
  console.log(`   API Key : ${API_KEY}`);
  console.log(`   Admin PW: ${ADMIN_PW}`);
  console.log(`   Data is IN-MEMORY — resets on restart\n`);
});
