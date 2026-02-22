require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const path    = require('path');
const jwt     = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const VPS_URL    = process.env.VPS_URL;
const API_KEY    = process.env.API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || API_KEY || 'msb-jwt-secret';
const PORT       = process.env.PORT || 3000;

if (!VPS_URL || !API_KEY) {
  console.warn('[WARN] VPS_URL or API_KEY not set — VPS requests will fail.');
}

const vps = (method, endpoint, data, adminKey) => {
  const headers = { 'x-api-key': API_KEY };
  if (adminKey) headers['x-admin-key'] = adminKey;
  return axios({ method, url: `${VPS_URL}${endpoint}`, data, headers, timeout: 40000 });
};

const requireAuth = (req, res, next) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
};

// ─── Auth ─────────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  try {
    const { data } = await vps('post', '/register', req.body);
    const token = jwt.sign(
      { id: data.user.id, username: data.user.username, email: data.user.email, name: data.user.name },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ success: true, token, user: data.user });
  } catch (e) {
    const msg = e.response?.data?.error || 'Registration failed.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { data } = await vps('post', '/login', req.body);
    const token = jwt.sign(
      { id: data.user.id, username: data.user.username, email: data.user.email, name: data.user.name },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ success: true, token, user: data.user });
  } catch (e) {
    const msg = e.response?.data?.error || 'Login failed.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

// ─── User Routes ──────────────────────────────────────────────────────────────

app.get('/api/user/me', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('get', `/users/${req.user.id}`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load user data.' });
  }
});

app.get('/api/user/deployments', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('get', `/users/${req.user.id}/deployments`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load deployments.' });
  }
});

app.get('/api/user/transactions', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('get', `/users/${req.user.id}/transactions`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load transactions.' });
  }
});

app.post('/api/deploy', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('post', '/deploy', {
      userId: req.user.id,
      sessionId: req.body.sessionId,
      appName: req.body.appName
    });
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Deployment failed.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.delete('/api/deploy/:botId', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('delete', `/deploy/${req.params.botId}`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to stop bot.' });
  }
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────

app.post('/api/admin/auth', async (req, res) => {
  try {
    const { data } = await vps('post', '/admin/auth', { password: req.body.password });
    res.json(data);
  } catch (e) {
    res.status(403).json({ error: 'Invalid admin password.' });
  }
});

app.get('/api/admin/stats', async (req, res) => {
  try {
    const { data } = await vps('get', '/admin/stats', null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load stats.' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    const { data } = await vps('get', '/admin/users', null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load users.' });
  }
});

app.post('/api/admin/topup', async (req, res) => {
  const { username, amount } = req.body;
  try {
    const { data } = await vps('post', `/admin/users/${username}/topup`, { amount }, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Top-up failed.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.get('/api/admin/deployments', async (req, res) => {
  try {
    const { data } = await vps('get', '/admin/deployments', null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load deployments.' });
  }
});

app.delete('/api/admin/users/:username', async (req, res) => {
  try {
    const { data } = await vps('delete', `/admin/users/${req.params.username}`, null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Failed to delete user.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.delete('/api/admin/deployments/:botId', async (req, res) => {
  try {
    const { data } = await vps('delete', `/admin/deployments/${req.params.botId}`, null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to stop bot.' });
  }
});

// ─── Payment Routes ───────────────────────────────────────────────────────────

app.post('/api/payments/submit', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('post', '/payment-requests', { userId: req.user.id, ...req.body });
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Failed to submit payment request.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.get('/api/payments/mine', requireAuth, async (req, res) => {
  try {
    const { data } = await vps('get', `/users/${req.user.id}/payment-requests`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load payment requests.' });
  }
});

app.get('/api/admin/payment-requests', async (req, res) => {
  try {
    const { data } = await vps('get', '/admin/payment-requests', null, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load payment requests.' });
  }
});

app.post('/api/admin/payment-requests/:id/approve', async (req, res) => {
  try {
    const { data } = await vps('post', `/admin/payment-requests/${req.params.id}/approve`, {}, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Failed to approve.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

app.post('/api/admin/payment-requests/:id/reject', async (req, res) => {
  try {
    const { data } = await vps('post', `/admin/payment-requests/${req.params.id}/reject`, {}, req.headers['x-admin-key']);
    res.json(data);
  } catch (e) {
    const msg = e.response?.data?.error || 'Failed to reject.';
    res.status(e.response?.status || 500).json({ error: msg });
  }
});

// ─── Page Routes ──────────────────────────────────────────────────────────────

const page = (f) => (_, res) => res.sendFile(path.join(__dirname, 'public', f));

app.get('/login',     page('login.html'));
app.get('/signup',    page('signup.html'));
app.get('/dashboard', page('dashboard.html'));
app.get('/bots',      page('bots.html'));
app.get('/deploy',    page('deploy.html'));
app.get('/coins',     page('coins.html'));
app.get('/admin',     page('admin.html'));

app.listen(PORT, () => console.log(`Panel running on http://localhost:${PORT}`));
