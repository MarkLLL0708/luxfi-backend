const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const winston = require('winston');

// ─── LOGGER ───────────────────────────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// ─── SECURITY MIDDLEWARE ──────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: true,
  crossOriginEmbedderPolicy: true,
}));

// Production-only CORS
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? ['https://luxfivault.netlify.app']
  : ['https://luxfivault.netlify.app', 'http://localhost:5173'];

app.use(cors({ origin: allowedOrigins, credentials: true }));

// Body size limit — prevent DDoS via large payloads
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Sanitize inputs — prevent NoSQL injection
app.use(mongoSanitize());

// Global rate limit
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } }));

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts' }
});

// ─── INPUT SANITIZER ─────────────────────────────────────
const sanitize = (obj) => {
  if (typeof obj === 'string') return xss(obj.trim());
  if (typeof obj === 'object' && obj !== null) {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, sanitize(v)])
    );
  }
  return obj;
};

// ─── SAFE ERROR RESPONSE ─────────────────────────────────
const safeError = (res, status, message) => {
  // Never expose internal error details
  logger.error({ status, message });
  return res.status(status).json({ error: message });
};

// ─── REQUEST LOGGER ───────────────────────────────────────
app.use((req, res, next) => {
  logger.info({ method: req.method, path: req.path, ip: req.ip });
  next();
});

// ─── JWT MIDDLEWARE ───────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return safeError(res, 401, 'Access token required');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return safeError(res, 403, 'Invalid or expired token');
  }
};

// ─── HEALTH (public) ─────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'LUXFI Backend Online', time: new Date() }));

// ─── AUTH ─────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { walletAddress, signature, message } = sanitize(req.body);

  if (!signature || !message || !walletAddress) {
    return safeError(res, 400, 'walletAddress, signature and message required');
  }

  // Validate wallet address format
  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
    return safeError(res, 400, 'Invalid wallet address format');
  }

  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      return safeError(res, 401, 'Invalid wallet signature');
    }
  } catch {
    return safeError(res, 401, 'Signature verification failed');
  }

  try {
    const { data: existing } = await supabase.from('users').select('*').eq('wallet_address', walletAddress).single();
    let user = existing;

    if (!user) {
      const { data, error } = await supabase.from('users').insert({ wallet_address: walletAddress }).select().single();
      if (error) return safeError(res, 500, 'Failed to create user');
      user = data;
    }

    const token = jwt.sign(
      { userId: user.id, walletAddress: user.wallet_address },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user });
  } catch {
    return safeError(res, 500, 'Authentication failed');
  }
});

// ─── BRANDS (public read) ─────────────────────────────────
app.get('/api/brands', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brands').select('*').order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch brands');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/brands/active', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brands').select('*').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch brands');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/brands/:id', async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('brands').select('*').eq('id', id).single();
    if (error) return safeError(res, 404, 'Brand not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/brands', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    const { data, error } = await supabase.from('brands').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create brand');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.put('/api/brands/:id', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const body = sanitize(req.body);
    const { data, error } = await supabase.from('brands').update(body).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to update brand');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── USERS (protected) ───────────────────────────────────
app.get('/api/users/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('users').select('*').eq('wallet_address', wallet).single();
    if (error) return safeError(res, 404, 'User not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.put('/api/users/:id/kyc', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { status } = sanitize(req.body);
    const validStatuses = ['pending', 'approved', 'rejected'];
    if (!validStatuses.includes(status)) return safeError(res, 400, 'Invalid KYC status');
    const { data, error } = await supabase.from('users').update({ kyc_status: status }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to update KYC');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── TRANSACTIONS (protected) ────────────────────────────
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('transactions').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/transactions/brand/:brandId', authenticateToken, async (req, res) => {
  try {
    const brandId = sanitize(req.params.brandId);
    const { data, error } = await supabase.from('transactions').select('*').eq('brand_id', brandId).order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    const { data, error } = await supabase.from('transactions').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create transaction');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── REWARDS ─────────────────────────────────────────────
app.get('/api/rewards/pools', async (req, res) => {
  try {
    const { data, error } = await supabase.from('reward_pools').select('*, brands(name)').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch reward pools');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/rewards/user/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = sanitize(req.params.userId);
    const { data, error } = await supabase.from('reward_claims').select('*, reward_pools(*, brands(name))').eq('user_id', userId);
    if (error) return safeError(res, 500, 'Failed to fetch rewards');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/rewards/claim', authenticateToken, async (req, res) => {
  try {
    const { poolId, userId } = sanitize(req.body);
    if (!poolId || !userId) return safeError(res, 400, 'poolId and userId required');
    const { data, error } = await supabase.from('reward_claims').update({ status: 'claimed', claimed_at: new Date().toISOString() }).eq('reward_pool_id', poolId).eq('user_id', userId).select().single();
    if (error) return safeError(res, 500, 'Failed to claim reward');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── GOVERNANCE ───────────────────────────────────────────
app.get('/api/governance', async (req, res) => {
  try {
    const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch proposals');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/governance/active', async (req, res) => {
  try {
    const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').eq('status', 'active').gt('deadline', new Date().toISOString());
    if (error) return safeError(res, 500, 'Failed to fetch proposals');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/governance', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.title || !body.brand_id) return safeError(res, 400, 'title and brand_id required');
    const { data, error } = await supabase.from('governance_proposals').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create proposal');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/governance/vote', authenticateToken, async (req, res) => {
  try {
    const { proposalId, userId, option, votingPower } = sanitize(req.body);
    if (!proposalId || !userId || !option) return safeError(res, 400, 'proposalId, userId and option required');
    const { data: existing } = await supabase.from('votes').select('id').eq('proposal_id', proposalId).eq('user_id', userId).single();
    if (existing) return safeError(res, 400, 'Already voted on this proposal');
    const { data, error } = await supabase.from('votes').insert({ proposal_id: proposalId, user_id: userId, option, voting_power: votingPower || 1 }).select().single();
    if (error) return safeError(res, 500, 'Failed to cast vote');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── MARKETPLACE ──────────────────────────────────────────
app.get('/api/marketplace', async (req, res) => {
  try {
    const { data, error } = await supabase.from('marketplace_listings').select('*, brands(name)').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch listings');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/marketplace', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.brand_id || !body.price_bnb) return safeError(res, 400, 'brand_id and price_bnb required');
    if (body.price_bnb <= 0) return safeError(res, 400, 'Price must be greater than 0');
    const { data, error } = await supabase.from('marketplace_listings').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create listing');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.put('/api/marketplace/:id/purchase', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { buyerWallet, txHash } = sanitize(req.body);
    if (!buyerWallet || !txHash) return safeError(res, 400, 'buyerWallet and txHash required');
    if (!/^0x[a-fA-F0-9]{40}$/.test(buyerWallet)) return safeError(res, 400, 'Invalid wallet address');
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) return safeError(res, 400, 'Invalid transaction hash');
    const { data, error } = await supabase.from('marketplace_listings').update({ status: 'sold', buyer_wallet: buyerWallet, tx_hash: txHash, sold_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to process purchase');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.put('/api/marketplace/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('marketplace_listings').update({ status: 'cancelled' }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to cancel listing');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── MISSIONS (public read) ───────────────────────────────
app.get('/api/missions', async (req, res) => {
  try {
    const { city, mission_type, difficulty } = sanitize(req.query);
    let query = supabase.from('missions').select('*').eq('status', 'active').gt('deadline', new Date().toISOString()).order('created_at', { ascending: false });
    if (city) query = query.eq('city', city);
    if (mission_type) query = query.eq('mission_type', mission_type);
    if (difficulty) query = query.eq('difficulty', difficulty);
    const { data, error } = await query;
    if (error) return safeError(res, 500, 'Failed to fetch missions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/missions/leaderboard', async (req, res) => {
  try {
    const { data, error } = await supabase.from('leaderboard_weekly').select('*').limit(20);
    if (error) return safeError(res, 500, 'Failed to fetch leaderboard');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/missions/:id', async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('missions').select('*').eq('id', id).single();
    if (error) return safeError(res, 404, 'Mission not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/missions', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.codename || !body.brand_name || !body.city) return safeError(res, 400, 'codename, brand_name and city required');
    const { data, error } = await supabase.from('missions').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/missions/:id/claim', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { walletAddress, stakeTxHash } = sanitize(req.body);
    if (!walletAddress) return safeError(res, 400, 'walletAddress required');
    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) return safeError(res, 400, 'Invalid wallet address');
    const { data: mission } = await supabase.from('missions').select('*').eq('id', id).single();
    if (!mission || mission.status !== 'active') return safeError(res, 400, 'Mission not available');
    if (new Date(mission.deadline) < new Date()) return safeError(res, 400, 'Mission deadline passed');
    const { data, error } = await supabase.from('mission_claims').insert({ mission_id: id, agent_wallet: walletAddress, stake_tx_hash: stakeTxHash, stake_amount_bnb: mission.stake_required_bnb }).select().single();
    if (error) return safeError(res, 500, 'Failed to claim mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/missions/claims/:claimId/submit', authenticateToken, async (req, res) => {
  try {
    const claimId = sanitize(req.params.claimId);
    const { intel_text, intel_photos, intel_video_url, gps_lat, gps_lng } = sanitize(req.body);
    if (!intel_text) return safeError(res, 400, 'intel_text required');
    const { data, error } = await supabase.from('mission_claims').update({ status: 'submitted', intel_text, intel_photos, intel_video_url, gps_lat, gps_lng, gps_verified: !!(gps_lat && gps_lng), submitted_at: new Date().toISOString() }).eq('id', claimId).select().single();
    if (error) return safeError(res, 500, 'Failed to submit mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

app.post('/api/missions/claims/:claimId/approve', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const claimId = sanitize(req.params.claimId);
    const { error } = await supabase.rpc('approve_mission', { p_claim_id: claimId });
    if (error) return safeError(res, 500, 'Failed to approve mission');
    res.json({ success: true });
  } catch { safeError(res, 500, 'Server error'); }
});

app.get('/api/missions/agent/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const [profileRes, claimsRes] = await Promise.all([
      supabase.from('agent_profiles').select('*').eq('wallet_address', wallet).single(),
      supabase.from('mission_claims').select('*, missions(codename, mission_type, city, reward_bnb, difficulty)').eq('agent_wallet', wallet).order('claimed_at', { ascending: false }).limit(20)
    ]);
    res.json({ profile: profileRes.data, missions: claimsRes.data });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── 404 HANDLER ─────────────────────────────────────────
app.use((req, res) => {
  safeError(res, 404, 'Route not found');
});

// ─── GLOBAL ERROR HANDLER ────────────────────────────────
app.use((err, req, res, next) => {
  logger.error({ error: err.message, stack: err.stack });
  safeError(res, 500, 'Internal server error');
});

// ─── START ────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => logger.info({ message: `LUXFI Backend running on port ${PORT}` }));
