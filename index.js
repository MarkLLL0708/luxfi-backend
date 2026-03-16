const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

app.use(helmet());
app.use(cors({ origin: ['https://luxfivault.netlify.app', 'http://localhost:5173'], credentials: true }));
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ─── JWT MIDDLEWARE ───────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ─── HEALTH (public) ─────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'LUXFI Backend Online', time: new Date() }));

// ─── AUTH ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { walletAddress, signature, message } = req.body;

  if (!signature || !message || !walletAddress) {
    return res.status(400).json({ error: 'walletAddress, signature and message required' });
  }

  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid wallet signature' });
    }
  } catch {
    return res.status(401).json({ error: 'Signature verification failed' });
  }

  // Get or create user
  const { data: existing } = await supabase.from('users').select('*').eq('wallet_address', walletAddress).single();
  let user = existing;

  if (!user) {
    const { data, error } = await supabase.from('users').insert({ wallet_address: walletAddress }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    user = data;
  }

  // Issue JWT
  const token = jwt.sign(
    { userId: user.id, walletAddress: user.wallet_address },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user });
});

// ─── BRANDS (public) ─────────────────────────────────────
app.get('/api/brands', async (req, res) => {
  const { data, error } = await supabase.from('brands').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/brands/active', async (req, res) => {
  const { data, error } = await supabase.from('brands').select('*').eq('status', 'active');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/brands/:id', async (req, res) => {
  const { data, error } = await supabase.from('brands').select('*').eq('id', req.params.id).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/brands', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('brands').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/brands/:id', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('brands').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── USERS (protected) ───────────────────────────────────
app.get('/api/users/:wallet', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('users').select('*').eq('wallet_address', req.params.wallet).single();
  if (error) return res.status(404).json({ error: 'User not found' });
  res.json(data);
});

app.put('/api/users/:id/kyc', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('users').update({ kyc_status: req.body.status }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── TRANSACTIONS (protected) ────────────────────────────
app.get('/api/transactions', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('transactions').select('*').order('created_at', { ascending: false }).limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/transactions/brand/:brandId', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('transactions').select('*').eq('brand_id', req.params.brandId).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('transactions').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── REWARDS ─────────────────────────────────────────────
app.get('/api/rewards/pools', async (req, res) => {
  const { data, error } = await supabase.from('reward_pools').select('*, brands(name)').eq('status', 'active');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/rewards/user/:userId', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('reward_claims').select('*, reward_pools(*, brands(name))').eq('user_id', req.params.userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/rewards/claim', authenticateToken, async (req, res) => {
  const { poolId, userId } = req.body;
  const { data, error } = await supabase.from('reward_claims').update({ status: 'claimed', claimed_at: new Date().toISOString() }).eq('reward_pool_id', poolId).eq('user_id', userId).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── GOVERNANCE (public read, protected write) ────────────
app.get('/api/governance', async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/governance/active', async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').eq('status', 'active').gt('deadline', new Date().toISOString());
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/governance', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/governance/vote', authenticateToken, async (req, res) => {
  const { proposalId, userId, option, votingPower } = req.body;
  const { data: existing } = await supabase.from('votes').select('id').eq('proposal_id', proposalId).eq('user_id', userId).single();
  if (existing) return res.status(400).json({ error: 'Already voted' });
  const { data, error } = await supabase.from('votes').insert({ proposal_id: proposalId, user_id: userId, option, voting_power: votingPower || 1 }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── MARKETPLACE (public read, protected write) ───────────
app.get('/api/marketplace', async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').select('*, brands(name)').eq('status', 'active');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/marketplace', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/marketplace/:id/purchase', authenticateToken, async (req, res) => {
  const { buyerWallet, txHash } = req.body;
  const { data, error } = await supabase.from('marketplace_listings').update({ status: 'sold', buyer_wallet: buyerWallet, tx_hash: txHash, sold_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/marketplace/:id/cancel', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').update({ status: 'cancelled' }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── MISSIONS (public read, protected write) ──────────────
app.get('/api/missions', async (req, res) => {
  const { city, mission_type, difficulty } = req.query;
  let query = supabase.from('missions').select('*').eq('status', 'active').gt('deadline', new Date().toISOString()).order('created_at', { ascending: false });
  if (city) query = query.eq('city', city);
  if (mission_type) query = query.eq('mission_type', mission_type);
  if (difficulty) query = query.eq('difficulty', difficulty);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/missions/leaderboard', async (req, res) => {
  const { data, error } = await supabase.from('leaderboard_weekly').select('*').limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/missions/:id', async (req, res) => {
  const { data, error } = await supabase.from('missions').select('*').eq('id', req.params.id).single();
  if (error) return res.status(404).json({ error: 'Mission not found' });
  res.json(data);
});

app.post('/api/missions', authenticateToken, async (req, res) => {
  const { data, error } = await supabase.from('missions').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/missions/:id/claim', authenticateToken, async (req, res) => {
  const { walletAddress, stakeTxHash } = req.body;
  const { data: mission } = await supabase.from('missions').select('*').eq('id', req.params.id).single();
  if (!mission || mission.status !== 'active') return res.status(400).json({ error: 'Mission not available' });
  const { data, error } = await supabase.from('mission_claims').insert({ mission_id: req.params.id, agent_wallet: walletAddress, stake_tx_hash: stakeTxHash, stake_amount_bnb: mission.stake_required_bnb }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/missions/claims/:claimId/submit', authenticateToken, async (req, res) => {
  const { intel_text, intel_photos, intel_video_url, gps_lat, gps_lng } = req.body;
  const { data, error } = await supabase.from('mission_claims').update({ status: 'submitted', intel_text, intel_photos, intel_video_url, gps_lat, gps_lng, gps_verified: !!(gps_lat && gps_lng), submitted_at: new Date().toISOString() }).eq('id', req.params.claimId).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/missions/claims/:claimId/approve', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  const { error } = await supabase.rpc('approve_mission', { p_claim_id: req.params.claimId });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.get('/api/missions/agent/:wallet', authenticateToken, async (req, res) => {
  const [profileRes, claimsRes] = await Promise.all([
    supabase.from('agent_profiles').select('*').eq('wallet_address', req.params.wallet).single(),
    supabase.from('mission_claims').select('*, missions(codename, mission_type, city, reward_bnb, difficulty)').eq('agent_wallet', req.params.wallet).order('claimed_at', { ascending: false }).limit(20)
  ]);
  res.json({ profile: profileRes.data, missions: claimsRes.data });
});

// ─── START ────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('LUXFI Backend running on port ' + PORT));
