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

// ─── JURISDICTION BLOCKING ────────────────────────────────
// Block US IPs to avoid SEC issues
const BLOCKED_COUNTRIES = ['US', 'IR', 'KP', 'CU', 'SY'];

const checkJurisdiction = async (req, res, next) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
    const data = await response.json();
    if (BLOCKED_COUNTRIES.includes(data.countryCode)) {
      logger.warn({ message: 'Blocked jurisdiction', ip, country: data.countryCode });
      return safeError(res, 403, 'Service not available in your region');
    }
    next();
  } catch {
    // If geo check fails, allow through — don't block on error
    next();
  }
};

// ─── SECURITY MIDDLEWARE ──────────────────────────────────
app.use(helmet({ contentSecurityPolicy: true, crossOriginEmbedderPolicy: true }));

const allowedOrigins = process.env.NODE_ENV === 'production'
  ? ['https://luxfivault.netlify.app']
  : ['https://luxfivault.netlify.app', 'http://localhost:5173'];

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts' }
});

// ─── HELPERS ─────────────────────────────────────────────
const sanitize = (obj) => {
  if (typeof obj === 'string') return xss(obj.trim());
  if (typeof obj === 'object' && obj !== null) {
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, sanitize(v)]));
  }
  return obj;
};

const safeError = (res, status, message) => {
  logger.error({ status, message });
  return res.status(status).json({ error: message });
};

// Generate unique request ID for audit trail
const generateRequestId = () => Math.random().toString(36).substr(2, 9).toUpperCase();

// ─── TRANSACTION MONITORING ───────────────────────────────
const SUSPICIOUS_PATTERNS = {
  MAX_TRANSACTIONS_PER_HOUR: 50,
  MAX_CLAIMS_PER_DAY: 5,
  MIN_TIME_BETWEEN_TRADES_MS: 1000,
};

const transactionMonitor = async (walletAddress, action) => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { count } = await supabase
      .from('transactions')
      .select('*', { count: 'exact', head: true })
      .eq('user_wallet', walletAddress)
      .gte('created_at', oneHourAgo);

    if (count > SUSPICIOUS_PATTERNS.MAX_TRANSACTIONS_PER_HOUR) {
      logger.warn({ message: 'Suspicious activity detected', walletAddress, action, count });
      await supabase.from('audit_logs').insert({
        wallet_address: walletAddress,
        action: 'SUSPICIOUS_ACTIVITY',
        details: `High transaction count: ${count} in 1 hour`,
        severity: 'HIGH',
        created_at: new Date().toISOString()
      });
      return true; // is suspicious
    }
    return false;
  } catch {
    return false;
  }
};

// ─── AUDIT LOG ────────────────────────────────────────────
const auditLog = async (action, walletAddress, details, severity = 'INFO') => {
  try {
    await supabase.from('audit_logs').insert({
      action,
      wallet_address: walletAddress,
      details: JSON.stringify(details),
      severity,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    logger.error({ message: 'Audit log failed', err: err.message });
  }
};

// ─── REQUEST LOGGER ───────────────────────────────────────
app.use((req, res, next) => {
  req.requestId = generateRequestId();
  res.setHeader('X-Request-ID', req.requestId);
  logger.info({ requestId: req.requestId, method: req.method, path: req.path, ip: req.ip });
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

// ─── API VERSIONING ───────────────────────────────────────
const v1 = express.Router();
app.use('/api/v1', v1);
app.use('/api', v1);

// ─── HEALTH ───────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'LUXFI Backend Online', version: 'v1', time: new Date() }));
v1.get('/health', (req, res) => res.json({ status: 'LUXFI Backend Online', version: 'v1', time: new Date() }));

// ─── AUTH ─────────────────────────────────────────────────
v1.post('/auth/login', authLimiter, checkJurisdiction, async (req, res) => {
  const { walletAddress, signature, message } = sanitize(req.body);

  if (!signature || !message || !walletAddress) {
    return safeError(res, 400, 'walletAddress, signature and message required');
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
    return safeError(res, 400, 'Invalid wallet address format');
  }

  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      await auditLog('FAILED_LOGIN', walletAddress, { reason: 'Invalid signature' }, 'WARN');
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

    await auditLog('LOGIN', walletAddress, { userId: user.id }, 'INFO');
    res.json({ token, user });
  } catch {
    return safeError(res, 500, 'Authentication failed');
  }
});

// ─── BRANDS ───────────────────────────────────────────────
v1.get('/brands', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brands').select('*').order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch brands');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/brands/active', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brands').select('*').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch brands');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/brands/:id', async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('brands').select('*').eq('id', id).single();
    if (error) return safeError(res, 404, 'Brand not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/brands', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.name) return safeError(res, 400, 'name required');
    const { data, error } = await supabase.from('brands').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create brand');
    await auditLog('CREATE_BRAND', req.user.walletAddress, { brandName: body.name }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/brands/:id', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const body = sanitize(req.body);
    const { data, error } = await supabase.from('brands').update(body).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to update brand');
    await auditLog('UPDATE_BRAND', req.user.walletAddress, { brandId: id }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── USERS ────────────────────────────────────────────────
v1.get('/users/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('users').select('*').eq('wallet_address', wallet).single();
    if (error) return safeError(res, 404, 'User not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/users/:id/kyc', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { status } = sanitize(req.body);
    const validStatuses = ['pending', 'approved', 'rejected'];
    if (!validStatuses.includes(status)) return safeError(res, 400, 'Invalid KYC status');
    const { data, error } = await supabase.from('users').update({ kyc_status: status }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to update KYC');
    await auditLog('KYC_UPDATE', req.user.walletAddress, { userId: id, status }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── TRANSACTIONS ─────────────────────────────────────────
v1.get('/transactions', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('transactions').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/transactions/brand/:brandId', authenticateToken, async (req, res) => {
  try {
    const brandId = sanitize(req.params.brandId);
    const { data, error } = await supabase.from('transactions').select('*').eq('brand_id', brandId).order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/transactions', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.brand_id || !body.amount) return safeError(res, 400, 'brand_id and amount required');

    // Transaction monitoring
    const suspicious = await transactionMonitor(req.user.walletAddress, 'CREATE_TRANSACTION');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');

    const { data, error } = await supabase.from('transactions').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create transaction');
    await auditLog('CREATE_TRANSACTION', req.user.walletAddress, { amount: body.amount, brandId: body.brand_id }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── REWARDS ──────────────────────────────────────────────
v1.get('/rewards/pools', async (req, res) => {
  try {
    const { data, error } = await supabase.from('reward_pools').select('*, brands(name)').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch reward pools');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/rewards/user/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = sanitize(req.params.userId);
    const { data, error } = await supabase.from('reward_claims').select('*, reward_pools(*, brands(name))').eq('user_id', userId);
    if (error) return safeError(res, 500, 'Failed to fetch rewards');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/rewards/claim', authenticateToken, async (req, res) => {
  try {
    const { poolId, userId } = sanitize(req.body);
    if (!poolId || !userId) return safeError(res, 400, 'poolId and userId required');

    // Check suspicious activity
    const suspicious = await transactionMonitor(req.user.walletAddress, 'CLAIM_REWARD');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');

    const { data, error } = await supabase.from('reward_claims').update({ status: 'claimed', claimed_at: new Date().toISOString() }).eq('reward_pool_id', poolId).eq('user_id', userId).select().single();
    if (error) return safeError(res, 500, 'Failed to claim reward');
    await auditLog('CLAIM_REWARD', req.user.walletAddress, { poolId, userId }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── GOVERNANCE ───────────────────────────────────────────
v1.get('/governance', async (req, res) => {
  try {
    const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch proposals');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/governance/active', async (req, res) => {
  try {
    const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').eq('status', 'active').gt('deadline', new Date().toISOString());
    if (error) return safeError(res, 500, 'Failed to fetch proposals');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/governance', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.title || !body.brand_id) return safeError(res, 400, 'title and brand_id required');
    const { data, error } = await supabase.from('governance_proposals').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create proposal');
    await auditLog('CREATE_PROPOSAL', req.user.walletAddress, { title: body.title }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/governance/vote', authenticateToken, async (req, res) => {
  try {
    const { proposalId, userId, option, votingPower } = sanitize(req.body);
    if (!proposalId || !userId || !option) return safeError(res, 400, 'proposalId, userId and option required');
    const { data: existing } = await supabase.from('votes').select('id').eq('proposal_id', proposalId).eq('user_id', userId).single();
    if (existing) return safeError(res, 400, 'Already voted on this proposal');
    const { data, error } = await supabase.from('votes').insert({ proposal_id: proposalId, user_id: userId, option, voting_power: votingPower || 1 }).select().single();
    if (error) return safeError(res, 500, 'Failed to cast vote');
    await auditLog('CAST_VOTE', req.user.walletAddress, { proposalId, option }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── MARKETPLACE ──────────────────────────────────────────
v1.get('/marketplace', async (req, res) => {
  try {
    const { data, error } = await supabase.from('marketplace_listings').select('*, brands(name)').eq('status', 'active');
    if (error) return safeError(res, 500, 'Failed to fetch listings');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/marketplace', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.brand_id || !body.price_bnb) return safeError(res, 400, 'brand_id and price_bnb required');
    if (body.price_bnb <= 0) return safeError(res, 400, 'Price must be greater than 0');
    const { data, error } = await supabase.from('marketplace_listings').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create listing');
    await auditLog('CREATE_LISTING', req.user.walletAddress, { brandId: body.brand_id, price: body.price_bnb }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/marketplace/:id/purchase', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { buyerWallet, txHash } = sanitize(req.body);
    if (!buyerWallet || !txHash) return safeError(res, 400, 'buyerWallet and txHash required');
    if (!/^0x[a-fA-F0-9]{40}$/.test(buyerWallet)) return safeError(res, 400, 'Invalid wallet address');
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) return safeError(res, 400, 'Invalid transaction hash');

    const suspicious = await transactionMonitor(buyerWallet, 'MARKETPLACE_PURCHASE');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');

    const { data, error } = await supabase.from('marketplace_listings').update({ status: 'sold', buyer_wallet: buyerWallet, tx_hash: txHash, sold_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to process purchase');
    await auditLog('MARKETPLACE_PURCHASE', buyerWallet, { listingId: id, txHash }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/marketplace/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('marketplace_listings').update({ status: 'cancelled' }).eq('id', id).select().single();
    if (error) return safeError(res, 500, 'Failed to cancel listing');
    await auditLog('CANCEL_LISTING', req.user.walletAddress, { listingId: id }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── MISSIONS ─────────────────────────────────────────────
v1.get('/missions', async (req, res) => {
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

v1.get('/missions/leaderboard', async (req, res) => {
  try {
    const { data, error } = await supabase.from('leaderboard_weekly').select('*').limit(20);
    if (error) return safeError(res, 500, 'Failed to fetch leaderboard');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/missions/:id', async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('missions').select('*').eq('id', id).single();
    if (error) return safeError(res, 404, 'Mission not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.codename || !body.brand_name || !body.city) return safeError(res, 400, 'codename, brand_name and city required');
    const { data, error } = await supabase.from('missions').insert(body).select().single();
    if (error) return safeError(res, 500, 'Failed to create mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/:id/claim', authenticateToken, async (req, res) => {
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
    await auditLog('CLAIM_MISSION', walletAddress, { missionId: id }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/claims/:claimId/submit', authenticateToken, async (req, res) => {
  try {
    const claimId = sanitize(req.params.claimId);
    const { intel_text, intel_photos, intel_video_url, gps_lat, gps_lng } = sanitize(req.body);
    if (!intel_text) return safeError(res, 400, 'intel_text required');
    const { data, error } = await supabase.from('mission_claims').update({ status: 'submitted', intel_text, intel_photos, intel_video_url, gps_lat, gps_lng, gps_verified: !!(gps_lat && gps_lng), submitted_at: new Date().toISOString() }).eq('id', claimId).select().single();
    if (error) return safeError(res, 500, 'Failed to submit mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/claims/:claimId/approve', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const claimId = sanitize(req.params.claimId);
    const { error } = await supabase.rpc('approve_mission', { p_claim_id: claimId });
    if (error) return safeError(res, 500, 'Failed to approve mission');
    await auditLog('APPROVE_MISSION', 'admin', { claimId }, 'INFO');
    res.json({ success: true });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/missions/agent/:wallet', authenticateToken, async (req, res) => {
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

// ─── AUDIT LOG ENDPOINT (admin only) ─────────────────────
v1.get('/admin/audit-logs', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { data, error } = await supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) return safeError(res, 500, 'Failed to fetch audit logs');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── SUSPICIOUS ACTIVITY REPORT (admin only) ─────────────
v1.get('/admin/suspicious', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { data, error } = await supabase.from('audit_logs').select('*').eq('severity', 'HIGH').order('created_at', { ascending: false }).limit(50);
    if (error) return safeError(res, 500, 'Failed to fetch suspicious activity');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── 404 HANDLER ─────────────────────────────────────────
app.use((req, res) => safeError(res, 404, 'Route not found'));

// ─── GLOBAL ERROR HANDLER ────────────────────────────────
app.use((err, req, res, next) => {
  logger.error({ error: err.message, stack: err.stack });
  safeError(res, 500, 'Internal server error');
});

// ─── START ────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => logger.info({ message: `LUXFI Backend v1 running on port ${PORT}` }));
