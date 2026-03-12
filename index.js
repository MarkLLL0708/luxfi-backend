const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.use(helmet());
app.use(cors({ origin: ['https://luxfivault.netlify.app', 'http://localhost:5173'], credentials: true }));
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

app.get('/api/health', (req, res) => res.json({ status: 'LUXFI Backend Online', time: new Date() }));

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

app.post('/api/brands', async (req, res) => {
  const { data, error } = await supabase.from('brands').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/brands/:id', async (req, res) => {
  const { data, error } = await supabase.from('brands').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/users/:wallet', async (req, res) => {
  const { data, error } = await supabase.from('users').select('*').eq('wallet_address', req.params.wallet).single();
  if (error) return res.status(404).json({ error: 'User not found' });
  res.json(data);
});

app.post('/api/users/connect', async (req, res) => {
  const { walletAddress, email } = req.body;
  const { data: existing } = await supabase.from('users').select('*').eq('wallet_address', walletAddress).single();
  if (existing) return res.json(existing);
  const { data, error } = await supabase.from('users').insert({ wallet_address: walletAddress, email }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/users/:id/kyc', async (req, res) => {
  const { data, error } = await supabase.from('users').update({ kyc_status: req.body.status, kyc_provider_id: req.body.providerId }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/transactions', async (req, res) => {
  const { data, error } = await supabase.from('transactions').select('*').order('recorded_at', { ascending: false }).limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/transactions/today', async (req, res) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const { data, error } = await supabase.from('transactions').select('*').gte('recorded_at', today.toISOString());
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/transactions/brand/:brandId', async (req, res) => {
  const { data, error } = await supabase.from('transactions').select('*').eq('brand_id', req.params.brandId).order('recorded_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/transactions', async (req, res) => {
  const { data, error } = await supabase.from('transactions').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/rewards/pools', async (req, res) => {
  const { data, error } = await supabase.from('reward_pools').select('*, brands(name)').eq('active', true);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/rewards/pools', async (req, res) => {
  const { data, error } = await supabase.from('reward_pools').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/rewards/user/:userId', async (req, res) => {
  const { data, error } = await supabase.from('reward_claims').select('*, reward_pools(*, brands(name))').eq('user_id', req.params.userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/rewards/claim', async (req, res) => {
  const { poolId, userId } = req.body;
  const { data, error } = await supabase.from('reward_claims').update({ claimed: true, claimed_at: new Date().toISOString() }).eq('pool_id', poolId).eq('user_id', userId).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/governance', async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').order('start_time', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/governance/active', async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)').eq('status', 'active').gt('end_time', new Date().toISOString());
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/governance', async (req, res) => {
  const { data, error } = await supabase.from('governance_proposals').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/governance/vote', async (req, res) => {
  const { proposalId, userId, support, weight } = req.body;
  const { data, error } = await supabase.from('votes').insert({ proposal_id: proposalId, user_id: userId, support, weight }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/marketplace', async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').select('*, brands(name), users(wallet_address)').eq('active', true);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/marketplace', async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/marketplace/:id', async (req, res) => {
  const { data, error } = await supabase.from('marketplace_listings').update({ active: false }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('LUXFI Backend running on port ' + PORT));
