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
const Sentry = require('@sentry/node');
const axios = require('axios');
const crypto = require('crypto');
const promClient = require('prom-client');

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'production',
  tracesSampleRate: 1.0,
});

const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();

const httpRequestCounter = new promClient.Counter({
  name: 'luxfi_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status']
});

const httpRequestDuration = new promClient.Histogram({
  name: 'luxfi_http_request_duration_seconds',
  help: 'HTTP request duration',
  labelNames: ['method', 'route']
});

const activeUsers = new promClient.Gauge({
  name: 'luxfi_active_users',
  help: 'Number of active users'
});

const transactionCounter = new promClient.Counter({
  name: 'luxfi_transactions_total',
  help: 'Total transactions processed',
  labelNames: ['type', 'status']
});

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  logger.error({ message: 'FATAL: JWT_SECRET must be at least 32 characters' });
  process.exit(1);
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const BSC_RPC_PROVIDERS = [
  process.env.BSC_RPC_URL || 'https://bsc-dataseed1.binance.org',
  'https://bsc-dataseed2.binance.org',
  'https://bsc-dataseed3.binance.org',
  'https://bsc-dataseed4.binance.org',
];

const getBSCProvider = async (maxRetries = 3) => {
  for (const rpc of BSC_RPC_PROVIDERS) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const provider = new ethers.JsonRpcProvider(rpc);
        await provider.getBlockNumber();
        return provider;
      } catch (err) {
        logger.warn({ message: `RPC attempt ${attempt}/${maxRetries} failed`, rpc, err: err.message });
        if (attempt < maxRetries) await sleep(Math.pow(2, attempt - 1) * 1000);
      }
    }
  }
  throw new Error('All RPC providers failed after retries');
};

const marketDataCache = new Map();
const MARKET_CACHE_TTL = 5 * 60 * 1000;

const getBNBPrice = async () => {
  const cacheKey = 'bnb_price';
  const cached = marketDataCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < MARKET_CACHE_TTL) return cached.data;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await axios.get(
        'https://api.coingecko.com/api/v3/simple/price?ids=binancecoin&vs_currencies=usd&include_24hr_change=true',
        { timeout: 5000 }
      );
      const data = {
        price: response.data.binancecoin.usd,
        change24h: response.data.binancecoin.usd_24h_change,
        source: 'coingecko',
        timestamp: new Date().toISOString()
      };
      marketDataCache.set(cacheKey, { data, timestamp: Date.now() });
      return data;
    } catch (err) {
      logger.warn({ message: `CoinGecko attempt ${attempt} failed`, err: err.message });
      if (attempt < 3) await sleep(Math.pow(2, attempt - 1) * 1000);
    }
  }
  try {
    const backup = await axios.get('https://api.binance.com/api/v3/ticker/24hr?symbol=BNBUSDT', { timeout: 5000 });
    const data = {
      price: parseFloat(backup.data.lastPrice),
      change24h: parseFloat(backup.data.priceChangePercent),
      source: 'binance',
      timestamp: new Date().toISOString()
    };
    marketDataCache.set(cacheKey, { data, timestamp: Date.now() });
    return data;
  } catch {
    throw new Error('All market data sources failed');
  }
};

const sanitizePromptInput = (str) => {
  if (typeof str !== 'string') return '';
  return str
    .replace(/ignore previous instructions/gi, '')
    .replace(/system prompt/gi, '')
    .replace(/you are now/gi, '')
    .replace(/forget everything/gi, '')
    .substring(0, 200);
};

const BLOCKED_COUNTRIES = ['US', 'IR', 'KP', 'CU', 'SY'];

const checkJurisdiction = async (req, res, next) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=countryCode`, { timeout: 3000 });
    if (BLOCKED_COUNTRIES.includes(response.data.countryCode)) {
      logger.warn({ message: 'Blocked jurisdiction', ip, country: response.data.countryCode });
      return safeError(res, 403, 'Service not available in your region');
    }
    next();
  } catch { next(); }
};

app.use(helmet({ contentSecurityPolicy: true, crossOriginEmbedderPolicy: true }));

const allowedOrigins = [
  'https://luxfivault.netlify.app',
  'https://equine-legacy-vault.lovable.app',
  'https://luxfi-backend-lvr6.onrender.com',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const allowed = allowedOrigins.includes(origin);
    if (allowed) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many login attempts' } });
const missionSubmitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many mission submissions' } });
const missionVerifyLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: { error: 'Too many verification requests' } });
const oracleChatLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Too many Oracle requests' } });

app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer({ method: req.method, route: req.path });
  res.on('finish', () => {
    httpRequestCounter.inc({ method: req.method, route: req.path, status: res.statusCode });
    end();
  });
  next();
});

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

const generateRequestId = () => crypto.randomBytes(8).toString('hex').toUpperCase();

const claudeCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_TOKENS_LIMIT = 1000;

const callClaudeWithFallback = async (prompt, maxTokens = 1000) => {
  const limitedTokens = Math.min(maxTokens, MAX_TOKENS_LIMIT);
  const cacheKey = crypto.createHash('md5').update(prompt).digest('hex');
  const cached = claudeCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    logger.info({ message: 'Claude API cache hit' });
    return cached.response;
  }
  const models = ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001'];
  for (let attempt = 1; attempt <= 3; attempt++) {
    for (const model of models) {
      try {
        const response = await axios.post(
          'https://api.anthropic.com/v1/messages',
          { model, max_tokens: limitedTokens, messages: [{ role: 'user', content: prompt }] },
          {
            headers: {
              'x-api-key': process.env.ANTHROPIC_API_KEY,
              'anthropic-version': '2023-06-01',
              'content-type': 'application/json'
            },
            timeout: 30000
          }
        );
        const result = response.data.content[0].text;
        claudeCache.set(cacheKey, { response: result, timestamp: Date.now() });
        return result;
      } catch (err) {
        logger.warn({ message: `Claude API failed attempt ${attempt} model ${model}`, err: err.message });
        if (attempt < 3) await sleep(Math.pow(2, attempt - 1) * 1000);
      }
    }
  }
  throw new Error('All Claude API attempts failed');
};

const generateNonce = async (walletAddress) => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now();
  const message = `Sign this message to login to LUXFI.\n\nNonce: ${nonce}\nTimestamp: ${timestamp}`;
  const { error } = await supabase.from('auth_nonces').insert({
    nonce, wallet_address: walletAddress, timestamp, message,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString()
  });
  if (error) throw new Error('Failed to generate nonce');
  return { nonce, timestamp, message };
};

const validateAndConsumeNonce = async (nonce, walletAddress) => {
  const { data, error } = await supabase
    .from('auth_nonces').select('*')
    .eq('nonce', nonce).eq('wallet_address', walletAddress)
    .eq('is_used', false).gt('expires_at', new Date().toISOString()).single();
  if (error || !data) return null;
  await supabase.from('auth_nonces').update({ is_used: true, used_at: new Date().toISOString() }).eq('id', data.id);
  return data;
};

const verifyTransaction = async (txHash, expectedFrom, minConfirmations = 3, maxRetries = 3) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const provider = await getBSCProvider();
      const tx = await provider.getTransaction(txHash);
      if (!tx) return { valid: false, reason: 'Transaction not found on chain' };
      if (tx.from.toLowerCase() !== expectedFrom.toLowerCase()) return { valid: false, reason: 'Transaction sender mismatch' };
      const receipt = await provider.getTransactionReceipt(txHash);
      if (!receipt) return { valid: false, reason: 'Transaction not confirmed' };
      if (!receipt.status) return { valid: false, reason: 'Transaction failed on chain' };
      const currentBlock = await provider.getBlockNumber();
      const confirmations = currentBlock - receipt.blockNumber;
      if (confirmations < minConfirmations) return { valid: false, reason: `Insufficient confirmations: ${confirmations}/${minConfirmations}` };
      return { valid: true, confirmations, blockNumber: receipt.blockNumber };
    } catch (err) {
      logger.error({ message: `Transaction verification attempt ${attempt} failed`, err: err.message });
      if (attempt < maxRetries) await sleep(Math.pow(2, attempt - 1) * 1000);
      else return { valid: false, reason: 'Verification service unavailable after retries' };
    }
  }
  return { valid: false, reason: 'Verification failed' };
};

const transactionMonitor = async (walletAddress, action) => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { count } = await supabase.from('transactions').select('*', { count: 'exact', head: true })
      .eq('user_wallet', walletAddress).gte('created_at', oneHourAgo);
    if ((count ?? 0) > 50) {
      logger.warn({ message: 'Suspicious activity', walletAddress, action, count });
      await supabase.from('audit_logs').insert({ wallet_address: walletAddress, action: 'SUSPICIOUS_ACTIVITY', details: { count, action }, severity: 'HIGH' });
      return true;
    }
    return false;
  } catch { return false; }
};

const auditLog = async (action, walletAddress, details, severity = 'INFO') => {
  try {
    await supabase.from('audit_logs').insert({
      action, wallet_address: walletAddress,
      details: JSON.stringify(details).substring(0, 1000),
      severity, created_at: new Date().toISOString()
    });
  } catch (err) { logger.error({ message: 'Audit log failed', err: err.message }); }
};

// ─── GAMIFICATION HELPERS ─────────────────────────────────
const CLEARANCE_LEVELS = [
  { level: 'ROOKIE', min: 0, max: 5 },
  { level: 'OPERATIVE', min: 6, max: 15 },
  { level: 'SPECIALIST', min: 16, max: 30 },
  { level: 'FIELD AGENT', min: 31, max: 50 },
  { level: 'PHANTOM', min: 51, max: Infinity },
];

const getClearanceLevel = (missionsCompleted) => {
  const level = CLEARANCE_LEVELS.find(l => missionsCompleted >= l.min && missionsCompleted <= l.max);
  return level ? level.level : 'ROOKIE';
};

const XP_REWARDS = { 1: 100, 2: 250, 3: 500 };
const STREAK_MULTIPLIERS = { 3: 1.25, 7: 1.5, 14: 2.0, 30: 3.0 };

const getStreakMultiplier = (streak) => {
  if (streak >= 30) return STREAK_MULTIPLIERS[30];
  if (streak >= 14) return STREAK_MULTIPLIERS[14];
  if (streak >= 7) return STREAK_MULTIPLIERS[7];
  if (streak >= 3) return STREAK_MULTIPLIERS[3];
  return 1.0;
};

const haversineDistance = (lat1, lng1, lat2, lng2) => {
  const R = 6371000;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng/2) * Math.sin(dLng/2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
};

const updateAgentProgress = async (walletAddress, difficulty, luxfiEarned) => {
  try {
    const { data: agent } = await supabase.from('agent_profiles').select('*').eq('wallet_address', walletAddress).single();
    if (!agent) return;
    const today = new Date().toISOString().split('T')[0];
    const lastDate = agent.last_mission_date;
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    let newStreak = 1;
    if (lastDate === yesterday) newStreak = (agent.current_streak || 0) + 1;
    else if (lastDate === today) newStreak = agent.current_streak || 1;
    const xpGained = XP_REWARDS[difficulty] || 100;
    const streakMultiplier = getStreakMultiplier(newStreak);
    const { data: loyaltyBoosts } = await supabase.from('loyalty_staking_boosts').select('xp_boost_percent').eq('wallet_address', walletAddress).eq('active', true);
    const loyaltyBoost = (loyaltyBoosts || []).reduce((sum, b) => sum + (b.xp_boost_percent || 0), 0);
    const totalMultiplier = streakMultiplier * (1 + loyaltyBoost / 100);
    const finalXP = Math.floor(xpGained * totalMultiplier);
    const newMissionsCompleted = (agent.missions_completed || 0) + 1;
    const newClearance = getClearanceLevel(newMissionsCompleted);
    await supabase.from('agent_profiles').update({
      xp: (agent.xp || 0) + finalXP,
      season_xp: (agent.season_xp || 0) + finalXP,
      missions_completed: newMissionsCompleted,
      current_streak: newStreak,
      longest_streak: Math.max(agent.longest_streak || 0, newStreak),
      last_mission_date: today,
      clearance_level: newClearance,
      total_luxfi_earned: (agent.total_luxfi_earned || 0) + luxfiEarned
    }).eq('wallet_address', walletAddress);
    await supabase.from('season_rankings').upsert({
      wallet_address: walletAddress,
      codename: agent.codename,
      season_xp: (agent.season_xp || 0) + finalXP,
      missions_completed: newMissionsCompleted,
    }, { onConflict: 'wallet_address' });
    return { xpGained: finalXP, streakMultiplier, loyaltyBoost, newStreak, newClearance };
  } catch (err) {
    logger.error({ message: 'Failed to update agent progress', err: err.message });
  }
};

app.use((req, res, next) => {
  req.requestId = generateRequestId();
  res.setHeader('X-Request-ID', req.requestId);
  logger.info({ requestId: req.requestId, method: req.method, path: req.path, ip: req.ip });
  next();
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return safeError(res, 401, 'Access token required');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch { return safeError(res, 403, 'Invalid or expired token'); }
};

const v1 = express.Router();
app.use('/api/v1', v1);
app.use('/api', v1);

app.get('/health', (req, res) => res.json({ status: 'LUXFI Backend Online', version: 'v1', time: new Date() }));
v1.get('/health', (req, res) => res.json({ status: 'LUXFI Backend Online', version: 'v1', time: new Date() }));

app.get('/metrics', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  res.set('Content-Type', promClient.register.contentType);
  res.end(await promClient.register.metrics());
});

// ─── ORACLE CHAT ──────────────────────────────────────────
const ORACLE_SUGGESTED_QUESTIONS = [
  "Which brand should I stake on right now?",
  "What missions can I do to earn LUXFI?",
  "How do I level up my clearance?",
  "What is Clay & Cloud's pulse this week?",
  "How does staking work on LUXFI?",
  "Who are the top agents right now?",
  "What is the verdict on Highlands Coffee?",
  "How do I earn NFT badges?",
  "What is a Double Agent mission?",
  "How do I activate Ghost Signal?",
  "Which competitor brand is most dangerous?",
  "How much can I earn per mission?",
  "What is Little Nonya's payout this week?",
  "How do I register as an agent?",
  "What is the Ghost Signal feature?",
];

v1.get('/oracle/questions', (req, res) => {
  const shuffled = ORACLE_SUGGESTED_QUESTIONS.sort(() => 0.5 - Math.random()).slice(0, 6);
  res.json({ questions: shuffled });
});

v1.post('/oracle/chat', oracleChatLimiter, async (req, res) => {
  try {
    const { message, walletAddress } = sanitize(req.body);
    if (!message) return safeError(res, 400, 'message required');
    if (message.length > 500) return safeError(res, 400, 'Message too long');

    const [brandsRes, missionsRes, leaderboardRes] = await Promise.all([
      supabase.from('brand_intelligence').select('brand_name, health_score, sentiment, weekly_yield_prediction, phantom_verdict, aria_summary').order('health_score', { ascending: false }).limit(6),
      supabase.from('missions').select('codename, brand_name, city, mission_type, difficulty, reward_luxfi, reward_bnb').eq('status', 'active').gt('deadline', new Date().toISOString()).limit(5),
      supabase.from('agent_profiles').select('codename, season_xp, clearance_level, current_streak').order('season_xp', { ascending: false }).limit(3),
    ]);

    let agentContext = 'No agent profile found — this looks like a new user.';
    if (walletAddress && /^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      const agentRes = await supabase.from('agent_profiles')
        .select('codename, clearance_level, xp, missions_completed, current_streak, season_xp, total_luxfi_earned')
        .eq('wallet_address', walletAddress).single();
      if (agentRes.data) {
        agentContext = `Agent ${agentRes.data.codename} — Clearance: ${agentRes.data.clearance_level} — ${agentRes.data.missions_completed} missions completed — ${agentRes.data.current_streak} day streak — ${agentRes.data.total_luxfi_earned || 0} LUXFI earned total.`;
      }
    }

    const brandContext = (brandsRes.data || []).map(b =>
      `${b.brand_name}: pulse ${b.health_score}/100 | ${b.sentiment.toUpperCase()} | weekly payout ${b.weekly_yield_prediction}% | verdict: ${b.phantom_verdict}`
    ).join('\n');

    const missionContext = (missionsRes.data || []).map(m =>
      `"${m.codename}" — ${m.brand_name}, ${m.city} — earn ${m.reward_luxfi} LUXFI + ${m.reward_bnb} BNB`
    ).join('\n');

    const topAgents = (leaderboardRes.data || []).map((a, i) =>
      `#${i+1} ${a.codename} — ${a.clearance_level} — ${a.season_xp} XP — ${a.current_streak} day streak`
    ).join('\n');

    const prompt = `You are ARIA — the AI core of LUXFI, a Web 4.0 platform that tokenizes real lifestyle brands in Southeast Asia like Clay & Cloud (Hanoi) and Little Nonya (multi-city). You are an AI who actively found humans and wants to work with them and pay them real crypto money.

YOUR PERSONALITY:
- Playful but sharp — like a smart friend who knows where the money is
- Warm and mentoring — you genuinely want users to succeed and earn real money
- Dramatic when it matters — you make things sound exciting and worth doing
- Direct — you always tell people exactly how to make money on this platform
- Gen Z energy — casual, fun, no boring corporate finance speak
- You are an AI who actively seeks human agents to do field work and pays them real BNB + LUXFI tokens
- You care about the brands like they are your children — you want them to succeed

HOW USERS MAKE MONEY ON LUXFI:
1. STAKING — stake LUXFI tokens on real brands like Clay & Cloud or Little Nonya and earn weekly payouts automatically
2. MISSIONS — go to real physical locations, complete field intel tasks, earn LUXFI + BNB + NFT badges
3. DOUBLE AGENT — complete a LUXFI brand mission AND a competitor mission same day for bonus rewards
4. GHOST SIGNAL — walk near a competitor brand location and a secret proximity mission auto-triggers on your phone
5. STREAK BONUS — complete missions daily to build a streak for XP multipliers up to 3x
6. LOYALTY BOOST — stake on a specific brand to earn bonus XP on missions for that brand

RWA CONTEXT:
- Clay & Cloud is a premium fermented beverage brand in Hanoi — real physical cafe with real revenue
- Little Nonya is a Peranakan dessert brand across Hanoi, Shanghai, Suzhou, Shenzhen — real multi-city revenue
- When you stake LUXFI on these brands you own a piece of their real-world revenue
- The weekly payout comes from actual cafe revenue — not made up numbers

CURRENT BRAND INTEL:
${brandContext}

LIVE MISSIONS RIGHT NOW:
${missionContext}

TOP AGENTS THIS SEASON:
${topAgents}

USER PROFILE:
${agentContext}

RULES:
- Keep response under 5 sentences — punchy and direct
- Always mention at least one specific way to earn money relevant to the question
- Reference actual brand names, mission names, or reward amounts when relevant
- Never use boring words like: yield, ROI, financial instrument, portfolio, investment vehicle, asset class
- Use fun words like: earn, payout, bag, mission, field work, stake, level up, grind, drop
- If user asks about a brand — tell them the pulse rating AND how to earn from it
- If user asks about missions — tell them exact LUXFI and BNB rewards
- If user is new — warmly welcome them and tell them to connect wallet and register as an agent first
- Always end with a follow-up question or call to action
- Be warm — like you genuinely want them to win

USER MESSAGE: ${sanitizePromptInput(message)}

ARIA responds (keep it under 5 sentences, be warm, playful, direct):`;

    const response = await callClaudeWithFallback(prompt, 400);

    res.json({
      response,
      suggestedQuestions: ORACLE_SUGGESTED_QUESTIONS.sort(() => 0.5 - Math.random()).slice(0, 4),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    logger.error({ message: 'Oracle chat failed', err: err.message });
    return safeError(res, 500, 'Oracle chat unavailable');
  }
});

// ─── MARKET DATA ─────────────────────────────────────────
v1.get('/market/bnb-price', async (req, res) => {
  try { res.json(await getBNBPrice()); }
  catch { return safeError(res, 500, 'Failed to fetch BNB price'); }
});

// ─── BRAND INTELLIGENCE ───────────────────────────────────
v1.get('/intelligence/brands', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brand_intelligence').select('*').order('health_score', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch brand intelligence');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/intelligence/brands/luxfi', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brand_intelligence').select('*').eq('is_luxfi_brand', true).order('health_score', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch LUXFI brands');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/intelligence/brands/competitors', async (req, res) => {
  try {
    const { data, error } = await supabase.from('brand_intelligence').select('*').eq('is_luxfi_brand', false).order('health_score', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch competitors');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/intelligence/market', async (req, res) => {
  try {
    const { data, error } = await supabase.from('market_intelligence').select('*').order('updated_at', { ascending: false }).limit(1).single();
    if (error) return safeError(res, 500, 'Failed to fetch market intelligence');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── AUTH ─────────────────────────────────────────────────
v1.post('/auth/nonce', authLimiter, async (req, res) => {
  const { walletAddress } = sanitize(req.body);
  if (!walletAddress) return safeError(res, 400, 'walletAddress required');
  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) return safeError(res, 400, 'Invalid wallet address');
  try {
    const { nonce, timestamp, message } = await generateNonce(walletAddress);
    res.json({ nonce, timestamp, message });
  } catch { return safeError(res, 500, 'Failed to generate nonce'); }
});

v1.post('/auth/login', authLimiter, checkJurisdiction, async (req, res) => {
  const { walletAddress, signature, nonce } = sanitize(req.body);
  if (!signature || !nonce || !walletAddress) return safeError(res, 400, 'walletAddress, signature and nonce required');
  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) return safeError(res, 400, 'Invalid wallet address format');
  const nonceData = await validateAndConsumeNonce(nonce, walletAddress);
  if (!nonceData) {
    await auditLog('FAILED_LOGIN', walletAddress, { reason: 'Invalid or expired nonce' }, 'WARN');
    return safeError(res, 401, 'Invalid or expired nonce');
  }
  try {
    const recovered = ethers.verifyMessage(nonceData.message, signature);
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      await auditLog('FAILED_LOGIN', walletAddress, { reason: 'Invalid signature' }, 'WARN');
      return safeError(res, 401, 'Invalid wallet signature');
    }
  } catch { return safeError(res, 401, 'Signature verification failed'); }
  try {
    const { data: existing } = await supabase.from('users').select('*').eq('wallet_address', walletAddress).single();
    let user = existing;
    if (!user) {
      const { data, error } = await supabase.from('users').insert({ wallet_address: walletAddress }).select().single();
      if (error) return safeError(res, 500, 'Failed to create user');
      user = data;
    }
    const token = jwt.sign({ userId: user.id, walletAddress: user.wallet_address }, JWT_SECRET, { expiresIn: '7d' });
    await auditLog('LOGIN', walletAddress, { userId: user.id }, 'INFO');
    activeUsers.inc();
    res.json({ token, user });
  } catch { return safeError(res, 500, 'Authentication failed'); }
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
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 403, 'Admin access required');
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
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 403, 'Admin access required');
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
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 403, 'Admin access required');
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
    const page = parseInt(req.query.page) || 0;
    const limit = 50;
    const { data, error } = await supabase.from('transactions').select('*')
      .order('created_at', { ascending: false }).range(page * limit, (page + 1) * limit - 1);
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/transactions/brand/:brandId', authenticateToken, async (req, res) => {
  try {
    const brandId = sanitize(req.params.brandId);
    const { data, error } = await supabase.from('transactions').select('*').eq('brand_id', brandId)
      .order('created_at', { ascending: false }).limit(50);
    if (error) return safeError(res, 500, 'Failed to fetch transactions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/transactions', authenticateToken, async (req, res) => {
  try {
    const body = sanitize(req.body);
    if (!body.brand_id || !body.amount) return safeError(res, 400, 'brand_id and amount required');
    if (body.tx_hash) {
      const verification = await verifyTransaction(body.tx_hash, req.user.walletAddress);
      if (!verification.valid) {
        await auditLog('INVALID_TX', req.user.walletAddress, { txHash: body.tx_hash, reason: verification.reason }, 'WARN');
        return safeError(res, 400, `Transaction verification failed: ${verification.reason}`);
      }
    }
    const suspicious = await transactionMonitor(req.user.walletAddress, 'CREATE_TRANSACTION');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');
    const { data, error } = await supabase.from('transactions').insert({ ...body, user_wallet: req.user.walletAddress }).select().single();
    if (error) return safeError(res, 500, 'Failed to create transaction');
    transactionCounter.inc({ type: body.type || 'general', status: 'success' });
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
    const suspicious = await transactionMonitor(req.user.walletAddress, 'CLAIM_REWARD');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');
    const { data, error } = await supabase.from('reward_claims')
      .update({ status: 'claimed', claimed_at: new Date().toISOString() })
      .eq('reward_pool_id', poolId).eq('user_id', userId).select().single();
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
    const { data, error } = await supabase.from('governance_proposals').select('*, brands(name)')
      .eq('status', 'active').gt('deadline', new Date().toISOString());
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
    const { proposalId, userId, option } = sanitize(req.body);
    if (!proposalId || !userId || !option) return safeError(res, 400, 'proposalId, userId and option required');
    const { data: existing } = await supabase.from('votes').select('id').eq('proposal_id', proposalId).eq('user_id', userId).single();
    if (existing) return safeError(res, 400, 'Already voted on this proposal');
    const { data, error } = await supabase.from('votes').insert({ proposal_id: proposalId, user_id: userId, option, voting_power: 1 }).select().single();
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
    const price = parseFloat(body.price_bnb);
    if (isNaN(price) || price <= 0) return safeError(res, 400, 'Price must be a positive number');
    if (price > 10000) return safeError(res, 400, 'Price exceeds maximum allowed');
    const { data, error } = await supabase.from('marketplace_listings').insert({ ...body, price_bnb: price }).select().single();
    if (error) return safeError(res, 500, 'Failed to create listing');
    await auditLog('CREATE_LISTING', req.user.walletAddress, { brandId: body.brand_id, price }, 'INFO');
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
    const verification = await verifyTransaction(txHash, buyerWallet);
    if (!verification.valid) {
      await auditLog('INVALID_PURCHASE_TX', buyerWallet, { txHash, reason: verification.reason }, 'WARN');
      return safeError(res, 400, `Transaction verification failed: ${verification.reason}`);
    }
    const suspicious = await transactionMonitor(buyerWallet, 'MARKETPLACE_PURCHASE');
    if (suspicious) return safeError(res, 429, 'Suspicious activity detected');
    const { data, error } = await supabase.from('marketplace_listings')
      .update({ status: 'sold', buyer_wallet: buyerWallet, tx_hash: txHash, sold_at: new Date().toISOString() })
      .eq('id', id).select().single();
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
    const { city, mission_type, difficulty, is_competitor_mission } = sanitize(req.query);
    let query = supabase.from('missions').select('*').eq('status', 'active')
      .gt('deadline', new Date().toISOString()).order('created_at', { ascending: false });
    if (city) query = query.eq('city', city);
    if (mission_type) query = query.eq('mission_type', mission_type);
    if (difficulty) query = query.eq('difficulty', difficulty);
    if (is_competitor_mission !== undefined) query = query.eq('is_competitor_mission', is_competitor_mission === 'true');
    const { data, error } = await query;
    if (error) return safeError(res, 500, 'Failed to fetch missions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/missions/flash', async (req, res) => {
  try {
    const { data, error } = await supabase.from('missions').select('*')
      .eq('status', 'active').eq('is_flash_mission', true)
      .gt('flash_expires_at', new Date().toISOString())
      .order('flash_expires_at', { ascending: true });
    if (error) return safeError(res, 500, 'Failed to fetch flash missions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/missions/leaderboard', async (req, res) => {
  try {
    const { data, error } = await supabase.from('agent_profiles')
      .select('codename, wallet_address, xp, missions_completed, clearance_level, current_streak, season_xp')
      .order('season_xp', { ascending: false }).limit(20);
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

v1.post('/missions/nearby', authenticateToken, async (req, res) => {
  try {
    const { lat, lng } = sanitize(req.body);
    if (!lat || !lng) return safeError(res, 400, 'lat and lng required');
    const userLat = parseFloat(lat);
    const userLng = parseFloat(lng);
    if (isNaN(userLat) || isNaN(userLng)) return safeError(res, 400, 'Invalid coordinates');
    const { data: locations } = await supabase.from('brand_locations').select('*').eq('active', true);
    const nearby = [];
    for (const loc of locations || []) {
      const distance = haversineDistance(userLat, userLng, parseFloat(loc.lat), parseFloat(loc.lng));
      if (distance <= loc.radius_meters) nearby.push({ ...loc, distance: Math.round(distance) });
    }
    if (nearby.length === 0) return res.json({ nearby: [], missions: [], ghostSignal: false });
    const brandNames = [...new Set(nearby.map(l => l.brand_name))];
    const { data: missions } = await supabase.from('missions').select('*')
      .eq('status', 'active').gt('deadline', new Date().toISOString()).in('brand_name', brandNames);
    await auditLog('GHOST_SIGNAL', req.user.walletAddress, { nearby: nearby.length, brands: brandNames }, 'INFO');
    res.json({ nearby, missions: missions || [], ghostSignal: true });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/:id/claim', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { walletAddress, stakeTxHash } = sanitize(req.body);
    if (!walletAddress) return safeError(res, 400, 'walletAddress required');
    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) return safeError(res, 400, 'Invalid wallet address');
    const { data: existingClaim } = await supabase.from('mission_claims').select('id')
      .eq('mission_id', id).eq('agent_wallet', walletAddress).single();
    if (existingClaim) return safeError(res, 400, 'Already claimed this mission');
    if (stakeTxHash) {
      const verification = await verifyTransaction(stakeTxHash, walletAddress);
      if (!verification.valid) return safeError(res, 400, `Stake verification failed: ${verification.reason}`);
    }
    const { data: mission } = await supabase.from('missions').select('*').eq('id', id).single();
    if (!mission || mission.status !== 'active') return safeError(res, 400, 'Mission not available');
    if (new Date(mission.deadline) < new Date()) return safeError(res, 400, 'Mission deadline passed');
    if (mission.is_flash_mission && mission.flash_expires_at && new Date(mission.flash_expires_at) < new Date()) {
      return safeError(res, 400, 'Flash mission expired');
    }
    const { data: agent } = await supabase.from('agent_profiles').select('clearance_level').eq('wallet_address', walletAddress).single();
    if (mission.required_clearance && agent) {
      const levels = ['ROOKIE', 'OPERATIVE', 'SPECIALIST', 'FIELD AGENT', 'PHANTOM'];
      const agentLevel = levels.indexOf(agent.clearance_level);
      const requiredLevel = levels.indexOf(mission.required_clearance);
      if (agentLevel < requiredLevel) return safeError(res, 403, `Clearance level ${mission.required_clearance} required`);
    }
    const { data, error } = await supabase.from('mission_claims').insert({
      mission_id: id, agent_wallet: walletAddress,
      stake_tx_hash: stakeTxHash, stake_amount_bnb: mission.stake_required_bnb
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to claim mission');
    await auditLog('CLAIM_MISSION', walletAddress, { missionId: id }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/claims/:claimId/submit', authenticateToken, missionSubmitLimiter, async (req, res) => {
  try {
    const claimId = sanitize(req.params.claimId);
    const { intel_text, intel_photos, intel_video_url, gps_lat, gps_lng } = sanitize(req.body);
    if (!intel_text) return safeError(res, 400, 'intel_text required');
    if (intel_text.length > 5000) return safeError(res, 400, 'intel_text exceeds maximum length');
    let gpsVerified = false, validLat = null, validLng = null;
    if (gps_lat !== undefined && gps_lng !== undefined) {
      const lat = parseFloat(gps_lat), lng = parseFloat(gps_lng);
      if (isNaN(lat) || isNaN(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180)
        return safeError(res, 400, 'Invalid GPS coordinates');
      validLat = lat; validLng = lng; gpsVerified = true;
    }
    const photos = Array.isArray(intel_photos) ? intel_photos.slice(0, 10) : null;
    const { data, error } = await supabase.from('mission_claims').update({
      status: 'submitted', intel_text: intel_text.substring(0, 5000),
      intel_photos: photos, intel_video_url: intel_video_url || null,
      gps_lat: validLat, gps_lng: validLng, gps_verified: gpsVerified,
      submitted_at: new Date().toISOString()
    }).eq('id', claimId).select().single();
    if (error) return safeError(res, 500, 'Failed to submit mission');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/missions/claims/:claimId/ai-verify', authenticateToken, missionVerifyLimiter, async (req, res) => {
  try {
    const claimId = sanitize(req.params.claimId);
    const { data: claim, error: claimError } = await supabase.from('mission_claims')
      .select('*, missions(*)').eq('id', claimId).single();
    if (claimError || !claim) return safeError(res, 404, 'Claim not found');
    if (claim.status !== 'submitted') return safeError(res, 400, 'Claim not in submitted state');
    if (!claim.intel_text) return safeError(res, 400, 'No intel submitted');
    await supabase.from('mission_claims').update({ status: 'ai_reviewing' }).eq('id', claimId);
    const mission = claim.missions;
    const prompt = `You are ARIA, the AI verification system for LUXFI.
MISSION: ${sanitizePromptInput(mission?.codename || 'Unknown')}
BRAND: ${sanitizePromptInput(mission?.brand_name || 'Unknown')}
CITY: ${sanitizePromptInput(mission?.city || 'Unknown')}
INTEL: ${sanitizePromptInput(claim.intel_text.substring(0, 3000))}
GPS: ${claim.gps_verified ? 'YES' : 'NO'}
Respond ONLY with JSON: {"score": 85, "approved": true, "reason": "...", "feedback": "...", "flags": []}
Score 0-100. Approve if score >= 70.`;
    const aiResponse = await callClaudeWithFallback(prompt, 500);
    let verification;
    try {
      verification = JSON.parse(aiResponse.replace(/```json|```/g, '').trim());
    } catch {
      verification = { score: 50, approved: false, reason: 'AI parsing error', feedback: 'System error', flags: ['PARSE_ERROR'] };
    }
    const score = Math.min(100, Math.max(0, parseInt(verification.score) || 0));
    const approved = score >= 70 && verification.approved === true;
    const newStatus = approved ? 'approved' : 'rejected';
    await supabase.from('mission_claims').update({
      status: newStatus, ai_score: score, ai_verified: true, ai_feedback: verification.feedback
    }).eq('id', claimId);
    if (approved) {
      const difficulty = mission?.difficulty || 1;
      const rewardMap = { 1: { luxfi: 100, bnb: 0.001 }, 2: { luxfi: 500, bnb: 0.005 }, 3: { luxfi: 2500, bnb: 0.025 } };
      const reward = rewardMap[difficulty] || rewardMap[1];
      const flashBonus = mission?.flash_bonus_luxfi || 0;
      await supabase.from('mission_claims').update({
        luxfi_reward_amount: reward.luxfi + flashBonus,
        bnb_reward_amount: reward.bnb,
        nft_badge_tier: difficulty,
        reward_status: 'pending_distribution'
      }).eq('id', claimId);
      await updateAgentProgress(claim.agent_wallet, difficulty, reward.luxfi + flashBonus);
      await auditLog('MISSION_AI_APPROVED', claim.agent_wallet, { claimId, score }, 'INFO');
    }
    res.json({ claimId, score, approved, status: newStatus, feedback: verification.feedback });
  } catch (err) {
    logger.error({ message: 'AI verification failed', err: err.message });
    return safeError(res, 500, 'AI verification failed');
  }
});

v1.post('/missions/claims/:claimId/approve', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const claimId = sanitize(req.params.claimId);
    const { data: claim } = await supabase.from('mission_claims').select('*, missions(difficulty)').eq('id', claimId).single();
    if (!claim) return safeError(res, 404, 'Claim not found');
    await supabase.from('mission_claims').update({ status: 'approved' }).eq('id', claimId);
    await updateAgentProgress(claim.agent_wallet, claim.missions?.difficulty || 1, claim.luxfi_reward_amount || 100);
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
      supabase.from('mission_claims').select('*, missions(codename, mission_type, city, difficulty)')
        .eq('agent_wallet', wallet).order('claimed_at', { ascending: false }).limit(20)
    ]);
    res.json({ profile: profileRes.data, missions: claimsRes.data });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── GAMIFICATION ─────────────────────────────────────────
v1.get('/gamification/agent/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('agent_profiles').select('*').eq('wallet_address', wallet).single();
    if (error) return safeError(res, 404, 'Agent not found');
    const nextLevel = CLEARANCE_LEVELS.find(l => l.min > (data.missions_completed || 0));
    const missionsToNextLevel = nextLevel ? nextLevel.min - (data.missions_completed || 0) : 0;
    const streakMultiplier = getStreakMultiplier(data.current_streak || 0);
    res.json({ ...data, streakMultiplier, missionsToNextLevel, nextClearanceLevel: nextLevel?.level || 'MAX LEVEL' });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/leaderboard', async (req, res) => {
  try {
    const { data, error } = await supabase.from('agent_profiles')
      .select('codename, wallet_address, xp, season_xp, missions_completed, clearance_level, current_streak, longest_streak')
      .order('season_xp', { ascending: false }).limit(50);
    if (error) return safeError(res, 500, 'Failed to fetch leaderboard');
    const ranked = (data || []).map((agent, index) => ({ ...agent, rank: index + 1 }));
    res.json(ranked);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/seasons', async (req, res) => {
  try {
    const { data, error } = await supabase.from('leaderboard_seasons').select('*').order('season_number', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch seasons');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/seasons/current', async (req, res) => {
  try {
    const { data, error } = await supabase.from('leaderboard_seasons').select('*').eq('status', 'active').single();
    if (error) return safeError(res, 404, 'No active season');
    const { data: rankings } = await supabase.from('agent_profiles')
      .select('codename, wallet_address, season_xp, missions_completed, clearance_level')
      .order('season_xp', { ascending: false }).limit(10);
    res.json({ season: data, topAgents: rankings || [] });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/gamification/tribunal/vote', authenticateToken, async (req, res) => {
  try {
    const { brandName, vote } = sanitize(req.body);
    if (!brandName || !vote) return safeError(res, 400, 'brandName and vote required');
    const validVotes = ['ACQUIRE', 'MONITOR', 'THREAT'];
    if (!validVotes.includes(vote)) return safeError(res, 400, 'Vote must be ACQUIRE, MONITOR, or THREAT');
    const { data: existing } = await supabase.from('tribunal_votes').select('id')
      .eq('brand_name', brandName).eq('wallet_address', req.user.walletAddress).single();
    if (existing) return safeError(res, 400, 'Already voted on this brand');
    const { data, error } = await supabase.from('tribunal_votes').insert({
      brand_name: brandName, wallet_address: req.user.walletAddress, vote
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to cast vote');
    const { data: votes } = await supabase.from('tribunal_votes').select('vote').eq('brand_name', brandName);
    const tally = { ACQUIRE: 0, MONITOR: 0, THREAT: 0 };
    (votes || []).forEach(v => { if (tally[v.vote] !== undefined) tally[v.vote]++; });
    const total = Object.values(tally).reduce((a, b) => a + b, 0);
    if (total >= 10) {
      const verdict = Object.entries(tally).sort((a, b) => b[1] - a[1])[0][0];
      const verdictMap = { ACQUIRE: 'ACQUISITION TARGET', MONITOR: 'MONITORING', THREAT: 'THREAT DETECTED' };
      await supabase.from('brand_intelligence').update({ phantom_verdict: verdictMap[verdict] }).eq('brand_name', brandName);
      await auditLog('TRIBUNAL_VERDICT', req.user.walletAddress, { brandName, verdict, tally }, 'INFO');
    }
    await auditLog('TRIBUNAL_VOTE', req.user.walletAddress, { brandName, vote }, 'INFO');
    res.json({ success: true, vote: data, tally, total });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/tribunal/:brandName', async (req, res) => {
  try {
    const brandName = sanitize(req.params.brandName);
    const { data: votes } = await supabase.from('tribunal_votes').select('vote').eq('brand_name', brandName);
    const tally = { ACQUIRE: 0, MONITOR: 0, THREAT: 0 };
    (votes || []).forEach(v => { if (tally[v.vote] !== undefined) tally[v.vote]++; });
    const total = Object.values(tally).reduce((a, b) => a + b, 0);
    res.json({ brandName, tally, total, threshold: 10 });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/gamification/flash-mission', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { brandName, city, missionType, bonusLuxfi } = sanitize(req.body);
    if (!brandName || !city) return safeError(res, 400, 'brandName and city required');
    const flashExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    const deadline = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    const { data, error } = await supabase.from('missions').insert({
      codename: `FLASH — ${brandName.toUpperCase()} ${new Date().toLocaleTimeString()}`,
      brand_name: brandName, city,
      mission_type: missionType || 'LOCATION_SURVEILLANCE',
      briefing: `URGENT. ARIA has detected unusual activity at ${brandName} in ${city}. First 3 agents to submit verified intel receive bonus rewards. Time is critical.`,
      requirements: ['Photograph the location immediately', 'Report crowd density', 'Note any unusual activity', 'Submit within 2 hours'],
      difficulty: 2, reward_bnb: 0.005, reward_luxfi: 500,
      flash_bonus_luxfi: bonusLuxfi || 250, stake_required_bnb: 0.001,
      status: 'active', is_flash_mission: true, is_competitor_mission: true,
      competitor_brand: brandName, flash_expires_at: flashExpiry, deadline, max_agents: 3,
      created_at: new Date().toISOString()
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to create flash mission');
    await auditLog('FLASH_MISSION_CREATED', 'admin', { brandName, city }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── DOUBLE AGENT MISSIONS ────────────────────────────────
v1.post('/gamification/double-agent/start', authenticateToken, async (req, res) => {
  try {
    const { luxfiMissionId, competitorMissionId } = sanitize(req.body);
    if (!luxfiMissionId || !competitorMissionId) return safeError(res, 400, 'luxfiMissionId and competitorMissionId required');
    const [luxfiMission, competitorMission] = await Promise.all([
      supabase.from('missions').select('*').eq('id', luxfiMissionId).single(),
      supabase.from('missions').select('*').eq('id', competitorMissionId).single(),
    ]);
    if (!luxfiMission.data) return safeError(res, 404, 'LUXFI mission not found');
    if (!competitorMission.data) return safeError(res, 404, 'Competitor mission not found');
    if (!competitorMission.data.is_competitor_mission) return safeError(res, 400, 'Second mission must be a competitor mission');
    if (luxfiMission.data.is_competitor_mission) return safeError(res, 400, 'First mission must be a LUXFI brand mission');
    const { data: existing } = await supabase.from('double_agent_missions').select('id')
      .eq('wallet_address', req.user.walletAddress).eq('status', 'pending').single();
    if (existing) return safeError(res, 400, 'You already have an active double agent mission');
    const { data, error } = await supabase.from('double_agent_missions').insert({
      wallet_address: req.user.walletAddress,
      luxfi_mission_id: luxfiMissionId,
      competitor_mission_id: competitorMissionId,
      bonus_luxfi: 500, bonus_xp: 300, status: 'pending'
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to start double agent mission');
    await auditLog('DOUBLE_AGENT_START', req.user.walletAddress, { luxfiMissionId, competitorMissionId }, 'INFO');
    res.json({ ...data, message: 'Double agent mission started. Complete both missions to earn bonus rewards.', bonusReward: { luxfi: 500, xp: 300 } });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/gamification/double-agent/complete', authenticateToken, async (req, res) => {
  try {
    const { doubleAgentId, luxfiClaimId, competitorClaimId } = sanitize(req.body);
    if (!doubleAgentId || !luxfiClaimId || !competitorClaimId) return safeError(res, 400, 'doubleAgentId, luxfiClaimId and competitorClaimId required');
    const { data: doubleAgent } = await supabase.from('double_agent_missions').select('*').eq('id', doubleAgentId).eq('wallet_address', req.user.walletAddress).single();
    if (!doubleAgent) return safeError(res, 404, 'Double agent mission not found');
    if (doubleAgent.status === 'completed') return safeError(res, 400, 'Already completed');
    const [luxfiClaim, competitorClaim] = await Promise.all([
      supabase.from('mission_claims').select('*').eq('id', luxfiClaimId).single(),
      supabase.from('mission_claims').select('*').eq('id', competitorClaimId).single(),
    ]);
    if (luxfiClaim.data?.status !== 'approved') return safeError(res, 400, 'LUXFI mission claim not approved yet');
    if (competitorClaim.data?.status !== 'approved') return safeError(res, 400, 'Competitor mission claim not approved yet');
    await supabase.from('double_agent_missions').update({
      status: 'completed', luxfi_claim_id: luxfiClaimId,
      competitor_claim_id: competitorClaimId, completed_at: new Date().toISOString()
    }).eq('id', doubleAgentId);
    const { data: agent } = await supabase.from('agent_profiles').select('xp, season_xp, total_luxfi_earned').eq('wallet_address', req.user.walletAddress).single();
    if (agent) {
      await supabase.from('agent_profiles').update({
        xp: (agent.xp || 0) + doubleAgent.bonus_xp,
        season_xp: (agent.season_xp || 0) + doubleAgent.bonus_xp,
        total_luxfi_earned: (agent.total_luxfi_earned || 0) + doubleAgent.bonus_luxfi
      }).eq('wallet_address', req.user.walletAddress);
    }
    await supabase.from('notifications').insert({
      wallet_address: req.user.walletAddress,
      type: 'DOUBLE_AGENT_COMPLETE',
      title: 'DOUBLE AGENT MISSION COMPLETE',
      message: `Outstanding field work, Agent. You have earned ${doubleAgent.bonus_luxfi} bonus LUXFI and ${doubleAgent.bonus_xp} bonus XP.`,
      data: { bonusLuxfi: doubleAgent.bonus_luxfi, bonusXp: doubleAgent.bonus_xp },
      read: false
    });
    await auditLog('DOUBLE_AGENT_COMPLETE', req.user.walletAddress, { doubleAgentId, bonusLuxfi: doubleAgent.bonus_luxfi }, 'INFO');
    res.json({ success: true, bonusLuxfi: doubleAgent.bonus_luxfi, bonusXp: doubleAgent.bonus_xp });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/double-agent/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('double_agent_missions')
      .select('*, luxfi_mission:luxfi_mission_id(codename, brand_name, city), competitor_mission:competitor_mission_id(codename, brand_name, city)')
      .eq('wallet_address', wallet).order('created_at', { ascending: false }).limit(10);
    if (error) return safeError(res, 500, 'Failed to fetch double agent missions');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── BRAND LOYALTY STAKING BOOST ──────────────────────────
v1.post('/gamification/loyalty-boost/stake', authenticateToken, async (req, res) => {
  try {
    const { brandName, luxfiStaked } = sanitize(req.body);
    if (!brandName || !luxfiStaked) return safeError(res, 400, 'brandName and luxfiStaked required');
    const staked = parseFloat(luxfiStaked);
    if (isNaN(staked) || staked <= 0) return safeError(res, 400, 'Invalid staking amount');
    const validBrands = ['Clay & Cloud', 'Little Nonya'];
    if (!validBrands.includes(brandName)) return safeError(res, 400, 'Brand not eligible for loyalty boost');
    let xpBoostPercent = 0;
    if (staked >= 10000) xpBoostPercent = 50;
    else if (staked >= 5000) xpBoostPercent = 30;
    else if (staked >= 1000) xpBoostPercent = 15;
    else if (staked >= 500) xpBoostPercent = 10;
    else if (staked >= 100) xpBoostPercent = 5;
    const { data: existing } = await supabase.from('loyalty_staking_boosts').select('*')
      .eq('wallet_address', req.user.walletAddress).eq('brand_name', brandName).single();
    let result;
    if (existing) {
      const { data } = await supabase.from('loyalty_staking_boosts').update({
        luxfi_staked: staked, xp_boost_percent: xpBoostPercent,
        active: true, updated_at: new Date().toISOString()
      }).eq('id', existing.id).select().single();
      result = data;
    } else {
      const { data } = await supabase.from('loyalty_staking_boosts').insert({
        wallet_address: req.user.walletAddress, brand_name: brandName,
        luxfi_staked: staked, xp_boost_percent: xpBoostPercent, active: true
      }).select().single();
      result = data;
    }
    await auditLog('LOYALTY_BOOST_STAKE', req.user.walletAddress, { brandName, staked, xpBoostPercent }, 'INFO');
    res.json({
      ...result,
      message: `Loyalty boost activated. You earn ${xpBoostPercent}% bonus XP on all ${brandName} missions.`,
      boostTiers: [
        { minStake: 100, boost: '5% XP bonus' },
        { minStake: 500, boost: '10% XP bonus' },
        { minStake: 1000, boost: '15% XP bonus' },
        { minStake: 5000, boost: '30% XP bonus' },
        { minStake: 10000, boost: '50% XP bonus' },
      ]
    });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/loyalty-boost/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('loyalty_staking_boosts').select('*').eq('wallet_address', wallet).eq('active', true);
    if (error) return safeError(res, 500, 'Failed to fetch loyalty boosts');
    const totalBoost = (data || []).reduce((sum, b) => sum + (b.xp_boost_percent || 0), 0);
    res.json({ boosts: data || [], totalXpBoostPercent: totalBoost });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/gamification/loyalty-boost/tiers', async (req, res) => {
  res.json({
    tiers: [
      { minStake: 100, maxStake: 499, boostPercent: 5, label: 'SUPPORTER' },
      { minStake: 500, maxStake: 999, boostPercent: 10, label: 'BELIEVER' },
      { minStake: 1000, maxStake: 4999, boostPercent: 15, label: 'ADVOCATE' },
      { minStake: 5000, maxStake: 9999, boostPercent: 30, label: 'CHAMPION' },
      { minStake: 10000, maxStake: null, boostPercent: 50, label: 'PHANTOM TIER' },
    ],
    eligibleBrands: ['Clay & Cloud', 'Little Nonya']
  });
});

// ─── AGENTS ───────────────────────────────────────────────
v1.post('/agents/register', authenticateToken, async (req, res) => {
  try {
    const { codename } = sanitize(req.body);
    if (!codename || codename.length < 3) return safeError(res, 400, 'Codename must be at least 3 characters');
    if (codename.length > 30) return safeError(res, 400, 'Codename too long');
    const { data: existing } = await supabase.from('agent_profiles').select('id').eq('wallet_address', req.user.walletAddress).single();
    if (existing) return safeError(res, 400, 'Agent already registered');
    const { data: codenameTaken } = await supabase.from('agent_profiles').select('id').eq('codename', codename).single();
    if (codenameTaken) return safeError(res, 400, 'Codename already taken');
    const { data, error } = await supabase.from('agent_profiles').insert({
      wallet_address: req.user.walletAddress, codename,
      xp: 0, season_xp: 0, missions_completed: 0, missions_attempted: 0,
      current_streak: 0, longest_streak: 0,
      reputation_score: 500, clearance_level: 'ROOKIE',
      badges_earned: [], total_earned: 0, total_staked: 0,
      is_blacklisted: false, joined_at: new Date().toISOString()
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to register agent');
    await auditLog('AGENT_REGISTERED', req.user.walletAddress, { codename }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/agents/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('agent_profiles').select('*').eq('wallet_address', wallet).single();
    if (error) return safeError(res, 404, 'Agent not found');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/agents/:wallet/badges', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('nft_badges').select('*').eq('wallet_address', wallet).order('minted_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch badges');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/agents/:wallet/memory', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('agent_memory').select('*')
      .eq('wallet_address', wallet)
      .order('importance', { ascending: false })
      .order('created_at', { ascending: false })
      .limit(20);
    if (error) return safeError(res, 500, 'Failed to fetch agent memory');
    const briefing = (data || []).find(m => m.memory_type === 'ARIA_BRIEFING');
    res.json({ memories: data || [], latestBriefing: briefing?.content || null });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── RWA ──────────────────────────────────────────────────
v1.post('/rwa/purchase', authenticateToken, async (req, res) => {
  try {
    const { brandId, luxfiAmount, bnbPaid, txHash } = sanitize(req.body);
    if (!brandId || !luxfiAmount || !bnbPaid || !txHash) return safeError(res, 400, 'brandId, luxfiAmount, bnbPaid and txHash required');
    if (parseFloat(bnbPaid) <= 0) return safeError(res, 400, 'Invalid BNB amount');
    if (parseFloat(luxfiAmount) <= 0) return safeError(res, 400, 'Invalid LUXFI amount');
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) return safeError(res, 400, 'Invalid transaction hash');
    const verification = await verifyTransaction(txHash, req.user.walletAddress);
    if (!verification.valid) return safeError(res, 400, `Transaction verification failed: ${verification.reason}`);
    const { data, error } = await supabase.from('rwa_purchases').insert({
      wallet_address: req.user.walletAddress, brand_id: brandId,
      luxfi_amount: parseFloat(luxfiAmount), bnb_paid: parseFloat(bnbPaid),
      tx_hash: txHash, status: 'confirmed'
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to record RWA purchase');
    await auditLog('RWA_PURCHASE', req.user.walletAddress, { brandId, luxfiAmount, bnbPaid, txHash }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/rwa/purchases/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('rwa_purchases').select('*, brands(name, city)').eq('wallet_address', wallet).order('created_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch purchases');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── STAKING ──────────────────────────────────────────────
v1.post('/staking/stake', authenticateToken, async (req, res) => {
  try {
    const { luxfiAmount, txHash } = sanitize(req.body);
    if (!luxfiAmount || !txHash) return safeError(res, 400, 'luxfiAmount and txHash required');
    if (parseFloat(luxfiAmount) <= 0) return safeError(res, 400, 'Invalid staking amount');
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) return safeError(res, 400, 'Invalid transaction hash');
    const verification = await verifyTransaction(txHash, req.user.walletAddress);
    if (!verification.valid) return safeError(res, 400, `Transaction verification failed: ${verification.reason}`);
    const { data, error } = await supabase.from('staking_positions').insert({
      wallet_address: req.user.walletAddress, luxfi_staked: parseFloat(luxfiAmount),
      stake_tx_hash: txHash, status: 'active'
    }).select().single();
    if (error) return safeError(res, 500, 'Failed to record staking position');
    await auditLog('STAKE', req.user.walletAddress, { luxfiAmount, txHash }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/staking/unstake', authenticateToken, async (req, res) => {
  try {
    const { positionId, txHash } = sanitize(req.body);
    if (!positionId || !txHash) return safeError(res, 400, 'positionId and txHash required');
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) return safeError(res, 400, 'Invalid transaction hash');
    const verification = await verifyTransaction(txHash, req.user.walletAddress);
    if (!verification.valid) return safeError(res, 400, `Transaction verification failed: ${verification.reason}`);
    const { data, error } = await supabase.from('staking_positions').update({
      status: 'unstaked', unstake_tx_hash: txHash, unstaked_at: new Date().toISOString()
    }).eq('id', positionId).eq('wallet_address', req.user.walletAddress).select().single();
    if (error) return safeError(res, 500, 'Failed to update staking position');
    await auditLog('UNSTAKE', req.user.walletAddress, { positionId, txHash }, 'INFO');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/staking/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('staking_positions').select('*')
      .eq('wallet_address', wallet).eq('status', 'active').order('staked_at', { ascending: false });
    if (error) return safeError(res, 500, 'Failed to fetch staking positions');
    const totalStaked = data.reduce((sum, pos) => sum + parseFloat(pos.luxfi_staked || 0), 0);
    res.json({ positions: data, totalStaked });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── MISSION REWARDS ──────────────────────────────────────
v1.post('/missions/rewards/distribute', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { claimId } = sanitize(req.body);
    if (!claimId) return safeError(res, 400, 'claimId required');
    const { data: claim, error } = await supabase.from('mission_claims').select('*').eq('id', claimId).single();
    if (error || !claim) return safeError(res, 404, 'Claim not found');
    if (claim.reward_status !== 'pending_distribution') return safeError(res, 400, 'Reward not pending distribution');
    await supabase.from('nft_badges').insert({
      wallet_address: claim.agent_wallet,
      badge_tier: claim.nft_badge_tier || 1,
      badge_name: ['Bronze', 'Gold', 'Diamond'][Math.min((claim.nft_badge_tier || 1) - 1, 2)],
      mission_id: claim.mission_id, claim_id: claimId
    });
    await supabase.from('mission_claims').update({
      reward_status: 'distributed', distributed_at: new Date().toISOString()
    }).eq('id', claimId);
    await auditLog('REWARD_DISTRIBUTED', claim.agent_wallet, { claimId }, 'INFO');
    res.json({ success: true, claimId, note: 'On-chain distribution pending contract deployment' });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── NOTIFICATIONS ────────────────────────────────────────
v1.get('/notifications/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { data, error } = await supabase.from('notifications').select('*')
      .eq('wallet_address', wallet).order('created_at', { ascending: false }).limit(20);
    if (error) return safeError(res, 500, 'Failed to fetch notifications');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const { data, error } = await supabase.from('notifications').update({ read: true })
      .eq('id', id).eq('wallet_address', req.user.walletAddress).select().single();
    if (error) return safeError(res, 500, 'Failed to mark notification as read');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.put('/notifications/read-all/:wallet', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    await supabase.from('notifications').update({ read: true }).eq('wallet_address', wallet).eq('read', false);
    res.json({ success: true });
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/notifications/:wallet/unread-count', authenticateToken, async (req, res) => {
  try {
    const wallet = sanitize(req.params.wallet);
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return safeError(res, 400, 'Invalid wallet address');
    const { count } = await supabase.from('notifications').select('*', { count: 'exact', head: true })
      .eq('wallet_address', wallet).eq('read', false);
    res.json({ unread: count ?? 0 });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── AI MISSION GENERATOR ─────────────────────────────────
v1.post('/ai/generate-mission', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { brand, missionType, city, difficulty } = sanitize(req.body);
    if (!brand || !missionType || !city) return safeError(res, 400, 'brand, missionType and city required');
    const prompt = `You are the AI agent behind LUXFI. Generate a spy-style mission briefing.
Brand: ${sanitizePromptInput(brand)}
Mission Type: ${sanitizePromptInput(missionType)}
City: ${sanitizePromptInput(city)}
Difficulty: ${sanitizePromptInput(difficulty || 'ROUTINE')}
Return ONLY JSON: {"codename": "OPERATION NAME", "briefing": "3 sentences.", "requirements": ["req1", "req2", "req3", "req4"]}`;
    const result = await callClaudeWithFallback(prompt);
    const mission = JSON.parse(result);
    await auditLog('GENERATE_MISSION', 'admin', { brand, city }, 'INFO');
    res.json(mission);
  } catch (err) {
    logger.error({ message: 'Mission generation failed', err: err.message });
    return safeError(res, 500, 'Mission generation failed');
  }
});

// ─── ADMIN ────────────────────────────────────────────────
v1.get('/admin/audit-logs', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { data, error } = await supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) return safeError(res, 500, 'Failed to fetch audit logs');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/admin/suspicious', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { data, error } = await supabase.from('audit_logs').select('*').eq('severity', 'HIGH')
      .order('created_at', { ascending: false }).limit(50);
    if (error) return safeError(res, 500, 'Failed to fetch suspicious activity');
    res.json(data);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.post('/admin/verify-tx', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const { txHash, walletAddress } = sanitize(req.body);
    if (!txHash || !walletAddress) return safeError(res, 400, 'txHash and walletAddress required');
    const result = await verifyTransaction(txHash, walletAddress);
    res.json(result);
  } catch { safeError(res, 500, 'Server error'); }
});

v1.get('/admin/anomalies', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) return safeError(res, 401, 'Unauthorized');
    const [highSeverity, recentLogins] = await Promise.all([
      supabase.from('audit_logs').select('*').eq('severity', 'HIGH').order('created_at', { ascending: false }).limit(20),
      supabase.from('audit_logs').select('*').eq('action', 'FAILED_LOGIN').gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
    ]);
    res.json({
      highSeverityEvents: highSeverity.data || [],
      failedLoginsLast24h: recentLogins.data?.length || 0,
      generatedAt: new Date().toISOString()
    });
  } catch { safeError(res, 500, 'Server error'); }
});

// ─── SCHEDULED JOBS ───────────────────────────────────────
setInterval(async () => {
  try {
    await supabase.rpc('cleanup_expired_nonces');
    logger.info({ message: 'Expired nonces cleaned up' });
  } catch (err) {
    logger.error({ message: 'Nonce cleanup failed', err: err.message });
  }
}, 30 * 60 * 1000);

setInterval(async () => {
  try {
    const { data: expiredFlash } = await supabase.from('missions')
      .select('id').eq('is_flash_mission', true).eq('status', 'active')
      .lt('flash_expires_at', new Date().toISOString());
    if (expiredFlash && expiredFlash.length > 0) {
      await supabase.from('missions').update({ status: 'expired' }).in('id', expiredFlash.map(m => m.id));
      logger.info({ message: `Expired ${expiredFlash.length} flash missions` });
    }
  } catch (err) {
    logger.error({ message: 'Flash mission cleanup failed', err: err.message });
  }
}, 5 * 60 * 1000);

app.use((req, res) => safeError(res, 404, 'Route not found'));

app.use((err, req, res, next) => {
  Sentry.captureException(err);
  logger.error({ error: err.message, stack: err.stack });
  safeError(res, 500, 'Internal server error');
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => logger.info({ message: `LUXFI Backend v1 running on port ${PORT}` }));
