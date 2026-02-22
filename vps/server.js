const express  = require('express');
const { execSync } = require('child_process');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const Database = require('better-sqlite3');
const cron     = require('node-cron');
const bcrypt   = require('bcryptjs');

const app = express();
app.use(express.json());

const API_KEY          = process.env.API_KEY          || 'change-this-secret';
const ADMIN_PASSWORD   = process.env.ADMIN_PASSWORD   || 'admin123';
const BOT_TEMPLATE_DIR = process.env.BOT_TEMPLATE_DIR || '/opt/bot-template';
const BOTS_DIR         = process.env.BOTS_DIR         || '/opt/bots';
const DAILY_COIN_COST  = parseInt(process.env.DAILY_COIN_COST || '1');
const PORT             = process.env.PORT             || 3001;
const DB_PATH          = process.env.DB_PATH          || path.join(__dirname, 'panel.db');

// ─── Database ────────────────────────────────────────────────────────────────

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    name          TEXT    NOT NULL,
    phone         TEXT,
    password_hash TEXT    NOT NULL,
    coins         INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    bot_id          TEXT    UNIQUE NOT NULL,
    app_name        TEXT,
    session_preview TEXT,
    status          TEXT    DEFAULT 'running',
    deployed_at     TEXT    DEFAULT (datetime('now')),
    stopped_at      TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    amount      INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    description TEXT,
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS payment_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    package     TEXT    NOT NULL,
    amount_usd  REAL    NOT NULL,
    coins       INTEGER NOT NULL,
    screenshot  TEXT,
    note        TEXT,
    status      TEXT    DEFAULT 'pending',
    reviewed_at TEXT,
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

if (!fs.existsSync(BOTS_DIR)) fs.mkdirSync(BOTS_DIR, { recursive: true });

// ─── Middleware ───────────────────────────────────────────────────────────────

const requireApiKey = (req, res, next) => {
  if (req.headers['x-api-key'] !== API_KEY)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.headers['x-admin-key'] !== ADMIN_PASSWORD)
    return res.status(403).json({ error: 'Forbidden' });
  next();
};

// ─── Auth ─────────────────────────────────────────────────────────────────────

app.post('/register', requireApiKey, async (req, res) => {
  const { username, email, name, password } = req.body;
  if (!username || !email || !name || !password)
    return res.status(400).json({ error: 'All fields are required.' });

  if (!/^[a-z0-9_]{3,30}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3-30 chars: lowercase, numbers, underscores only.' });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address.' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username))
    return res.status(409).json({ error: 'Username already taken.' });

  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(409).json({ error: 'Email already registered.' });

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const result = db.prepare(
      'INSERT INTO users (username, email, name, password_hash, coins) VALUES (?, ?, ?, ?, 3)'
    ).run(username, email, name, password_hash);

    db.prepare(
      'INSERT INTO transactions (user_id, amount, type, description) VALUES (?, 3, ?, ?)'
    ).run(result.lastInsertRowid, 'credit', 'Welcome bonus');

    const user = db.prepare(
      'SELECT id, username, email, name, coins FROM users WHERE id = ?'
    ).get(result.lastInsertRowid);

    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/login', requireApiKey, async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password)
    return res.status(400).json({ error: 'Username/email and password are required.' });

  const user = db.prepare(
    'SELECT * FROM users WHERE username = ? OR email = ?'
  ).get(login, login);

  if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });

  res.json({
    success: true,
    user: { id: user.id, username: user.username, email: user.email, name: user.name, coins: user.coins }
  });
});

// ─── User Data ────────────────────────────────────────────────────────────────

app.get('/users/:id', requireApiKey, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, email, name, coins FROM users WHERE id = ?'
  ).get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const activeDeployment = db.prepare(
    "SELECT * FROM deployments WHERE user_id = ? AND status = 'running'"
  ).get(user.id);

  const totalBots    = db.prepare("SELECT COUNT(*) AS c FROM deployments WHERE user_id = ?").get(user.id).c;
  const activeBots   = db.prepare("SELECT COUNT(*) AS c FROM deployments WHERE user_id = ? AND status = 'running'").get(user.id).c;
  const inactiveBots = totalBots - activeBots;

  res.json({ ...user, activeDeployment: activeDeployment || null, totalBots, activeBots, inactiveBots });
});

app.get('/users/:id/deployments', requireApiKey, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM deployments WHERE user_id = ? ORDER BY deployed_at DESC"
  ).all(req.params.id);
  res.json(rows);
});

app.get('/users/:id/transactions', requireApiKey, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20"
  ).all(req.params.id);
  res.json(rows);
});

// ─── Deploy ───────────────────────────────────────────────────────────────────

app.post('/deploy', requireApiKey, (req, res) => {
  const { userId, sessionId, appName } = req.body;
  if (!userId || !sessionId)
    return res.status(400).json({ error: 'userId and sessionId are required.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  if (user.coins < DAILY_COIN_COST)
    return res.status(402).json({
      error: `Not enough coins. You need ${DAILY_COIN_COST} coin(s) to deploy. Contact admin to top up.`
    });

  const existing = db.prepare(
    "SELECT * FROM deployments WHERE user_id = ? AND status = 'running'"
  ).get(user.id);
  if (existing)
    return res.status(409).json({ error: 'You already have an active bot running.', botId: existing.bot_id });

  const botId  = `bot-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const botDir = path.join(BOTS_DIR, botId);
  const name   = appName || `msb-${user.username}`;

  try {
    fs.mkdirSync(botDir, { recursive: true });

    execSync(
      `rsync -a --exclude=node_modules --exclude='mayel/session/*' ` +
      `--exclude='mayel/temp/*' --exclude='*.db' ` +
      `"${BOT_TEMPLATE_DIR}/" "${botDir}/"`
    );

    const nmSrc  = path.join(BOT_TEMPLATE_DIR, 'node_modules');
    const nmDest = path.join(botDir, 'node_modules');
    if (fs.existsSync(nmSrc) && !fs.existsSync(nmDest))
      fs.symlinkSync(nmSrc, nmDest);

    // Write .env for apps that load dotenv themselves
    const envContent = [
      `SESSION_ID=${sessionId}`,
      `OWNER_NUMBER=${user.phone || ''}`,
      `BOT_NAME=MARK SUMO BOT`,
      `PREFIX=.`,
      `MODE=private`,
      `TIME_ZONE=Africa/Lagos`
    ].join('\n');
    fs.writeFileSync(path.join(botDir, '.env'), envContent);

    // Write PM2 ecosystem config — env vars passed directly, no dotenv needed
    const ecoConfig = {
      apps: [{
        name,
        script: 'index.js',
        cwd: botDir,
        env: {
          SESSION_ID: sessionId,
          OWNER_NUMBER: user.phone || '',
          BOT_NAME: 'MARK SUMO BOT',
          PREFIX: '.',
          MODE: 'private',
          TIME_ZONE: 'Africa/Lagos'
        }
      }]
    };
    fs.writeFileSync(
      path.join(botDir, 'ecosystem.config.js'),
      `module.exports = ${JSON.stringify(ecoConfig, null, 2)};`
    );

    execSync(`pm2 start "${path.join(botDir, 'ecosystem.config.js')}"`);
    execSync('pm2 save');

    db.prepare('UPDATE users SET coins = coins - ? WHERE id = ?').run(DAILY_COIN_COST, user.id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)')
      .run(user.id, -DAILY_COIN_COST, 'deploy', `Bot deployed: ${name}`);
    db.prepare('INSERT INTO deployments (user_id, bot_id, app_name, session_preview) VALUES (?, ?, ?, ?)')
      .run(user.id, botId, name, sessionId.substring(0, 30) + '...');

    const newCoins = db.prepare('SELECT coins FROM users WHERE id = ?').get(user.id).coins;
    res.json({ success: true, botId, coinsRemaining: newCoins });
  } catch (err) {
    try { fs.rmSync(botDir, { recursive: true, force: true }); } catch (_) {}
    res.status(500).json({ error: 'Deployment failed: ' + err.message });
  }
});

app.delete('/deploy/:botId/record', requireApiKey, (req, res) => {
  const dep = db.prepare('SELECT * FROM deployments WHERE bot_id = ?').get(req.params.botId);
  if (!dep) return res.status(404).json({ error: 'Bot not found.' });
  if (dep.status === 'running') return res.status(400).json({ error: 'Stop the bot before deleting.' });
  db.prepare('DELETE FROM deployments WHERE bot_id = ?').run(req.params.botId);
  res.json({ success: true });
});

app.delete('/deploy/:botId', requireApiKey, (req, res) => {
  const dep = db.prepare('SELECT * FROM deployments WHERE bot_id = ?').get(req.params.botId);
  if (!dep) return res.status(404).json({ error: 'Bot not found.' });

  try {
    execSync(`pm2 delete "${dep.app_name || dep.bot_id}" 2>/dev/null || true`);
    execSync('pm2 save');
  } catch (_) {}

  db.prepare(
    "UPDATE deployments SET status = 'stopped', stopped_at = datetime('now') WHERE bot_id = ?"
  ).run(req.params.botId);
  res.json({ success: true });
});

// ─── Admin ────────────────────────────────────────────────────────────────────

app.post('/admin/auth', requireApiKey, (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD)
    return res.status(403).json({ error: 'Invalid admin password.' });
  res.json({ success: true });
});

app.get('/admin/users', requireApiKey, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.name, u.phone, u.coins, u.created_at,
      (SELECT COUNT(*) FROM deployments WHERE user_id = u.id AND status = 'running') AS active_bots
    FROM users u ORDER BY u.created_at DESC
  `).all();
  res.json(users);
});

app.post('/admin/users/:username/topup', requireApiKey, requireAdmin, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0)
    return res.status(400).json({ error: 'Amount must be positive.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  db.prepare('UPDATE users SET coins = coins + ? WHERE username = ?').run(amount, req.params.username);
  db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)')
    .run(user.id, amount, 'topup', `Admin top-up: +${amount} coins`);

  const newCoins = db.prepare('SELECT coins FROM users WHERE username = ?').get(req.params.username).coins;
  res.json({ success: true, newCoins });
});

app.get('/admin/deployments', requireApiKey, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT d.*, u.username, u.email
    FROM deployments d JOIN users u ON u.id = d.user_id
    ORDER BY d.deployed_at DESC
  `).all();
  res.json(rows);
});

app.delete('/admin/deployments/:botId', requireApiKey, requireAdmin, (req, res) => {
  const dep = db.prepare('SELECT * FROM deployments WHERE bot_id = ?').get(req.params.botId);
  if (!dep) return res.status(404).json({ error: 'Bot not found.' });

  try {
    execSync(`pm2 delete "${dep.app_name || dep.bot_id}" 2>/dev/null || true`);
    execSync('pm2 save');
  } catch (_) {}

  db.prepare(
    "UPDATE deployments SET status = 'stopped_by_admin', stopped_at = datetime('now') WHERE bot_id = ?"
  ).run(req.params.botId);
  res.json({ success: true });
});

app.delete('/admin/users/:username', requireApiKey, requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // Stop any running bots
  const running = db.prepare("SELECT * FROM deployments WHERE user_id = ? AND status = 'running'").all(user.id);
  for (const dep of running) {
    try { execSync(`pm2 delete "${dep.app_name || dep.bot_id}" 2>/dev/null || true`); } catch (_) {}
  }
  if (running.length) { try { execSync('pm2 save'); } catch (_) {} }

  // Delete user data
  db.prepare('DELETE FROM transactions WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM deployments WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM payment_requests WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);

  res.json({ success: true });
});

app.get('/admin/stats', requireApiKey, requireAdmin, (req, res) => {
  res.json({
    totalUsers:       db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    activeBots:       db.prepare("SELECT COUNT(*) AS c FROM deployments WHERE status = 'running'").get().c,
    totalDeployments: db.prepare('SELECT COUNT(*) AS c FROM deployments').get().c,
    totalCoins:       db.prepare('SELECT COALESCE(SUM(coins),0) AS c FROM users').get().c,
    recentUsers: db.prepare(`
      SELECT u.username, u.email, u.name, u.coins, u.created_at,
        (SELECT COUNT(*) FROM deployments WHERE user_id = u.id AND status = 'running') AS active_bots
      FROM users u ORDER BY u.created_at DESC LIMIT 10
    `).all()
  });
});

// ─── Payment Requests ─────────────────────────────────────────────────────────

// Submit payment request (user)
app.post('/payment-requests', requireApiKey, (req, res) => {
  const { userId, package: pkg, amount_usd, coins, screenshot, note } = req.body;
  if (!userId || !pkg || !amount_usd || !coins)
    return res.status(400).json({ error: 'Missing required fields.' });

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // Limit pending requests to 1 at a time
  const pending = db.prepare(
    "SELECT id FROM payment_requests WHERE user_id = ? AND status = 'pending'"
  ).get(userId);
  if (pending)
    return res.status(409).json({ error: 'You already have a pending payment request. Wait for admin to review it.' });

  const result = db.prepare(
    'INSERT INTO payment_requests (user_id, package, amount_usd, coins, screenshot, note) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, pkg, amount_usd, coins, screenshot || null, note || null);

  res.json({ success: true, id: result.lastInsertRowid });
});

// Get user's payment requests
app.get('/users/:id/payment-requests', requireApiKey, (req, res) => {
  const rows = db.prepare(
    "SELECT id, package, amount_usd, coins, note, status, created_at, reviewed_at FROM payment_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 10"
  ).all(req.params.id);
  res.json(rows);
});

// Admin: get all payment requests
app.get('/admin/payment-requests', requireApiKey, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT p.*, u.username, u.email
    FROM payment_requests p JOIN users u ON u.id = p.user_id
    ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END, p.created_at DESC
  `).all();
  res.json(rows);
});

// Admin: approve payment request
app.post('/admin/payment-requests/:id/approve', requireApiKey, requireAdmin, (req, res) => {
  const pr = db.prepare('SELECT * FROM payment_requests WHERE id = ?').get(req.params.id);
  if (!pr) return res.status(404).json({ error: 'Request not found.' });
  if (pr.status !== 'pending') return res.status(400).json({ error: 'Request already reviewed.' });

  db.prepare('UPDATE payment_requests SET status = ?, reviewed_at = datetime(\'now\') WHERE id = ?')
    .run('approved', pr.id);
  db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(pr.coins, pr.user_id);
  db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)')
    .run(pr.user_id, pr.coins, 'topup', `Payment approved: ${pr.package} (+${pr.coins} coins)`);

  res.json({ success: true });
});

// Admin: reject payment request
app.post('/admin/payment-requests/:id/reject', requireApiKey, requireAdmin, (req, res) => {
  const pr = db.prepare('SELECT * FROM payment_requests WHERE id = ?').get(req.params.id);
  if (!pr) return res.status(404).json({ error: 'Request not found.' });
  if (pr.status !== 'pending') return res.status(400).json({ error: 'Request already reviewed.' });

  db.prepare('UPDATE payment_requests SET status = ?, reviewed_at = datetime(\'now\') WHERE id = ?')
    .run('rejected', pr.id);
  res.json({ success: true });
});

// ─── Cron: Daily coin deduction ───────────────────────────────────────────────

cron.schedule('0 0 * * *', () => {
  console.log('[CRON] Daily coin deduction...');
  const running = db.prepare(`
    SELECT d.*, u.coins, u.id AS uid
    FROM deployments d JOIN users u ON u.id = d.user_id
    WHERE d.status = 'running'
  `).all();

  for (const bot of running) {
    if (bot.coins < DAILY_COIN_COST) {
      try { execSync(`pm2 delete "${bot.app_name || bot.bot_id}" 2>/dev/null || true`); } catch (_) {}
      db.prepare(
        "UPDATE deployments SET status = 'stopped_no_coins', stopped_at = datetime('now') WHERE id = ?"
      ).run(bot.id);
      console.log(`[CRON] Stopped ${bot.bot_id} — insufficient coins`);
    } else {
      db.prepare('UPDATE users SET coins = coins - ? WHERE id = ?').run(DAILY_COIN_COST, bot.uid);
      db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)')
        .run(bot.uid, -DAILY_COIN_COST, 'daily', `Daily renewal: ${bot.app_name || bot.bot_id}`);
    }
  }
  try { execSync('pm2 save'); } catch (_) {}
});

app.listen(PORT, () => console.log(`VPS Manager running on port ${PORT}`));
