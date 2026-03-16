-- ─── AUDIT LOG TABLE ─────────────────────────────────────
create table if not exists audit_logs (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp default now(),
  action text not null,
  wallet_address text,
  details jsonb,
  severity text default 'INFO',
  ip_address text,
  request_id text
);

create index if not exists idx_audit_logs_wallet on audit_logs(wallet_address);
create index if not exists idx_audit_logs_severity on audit_logs(severity);
create index if not exists idx_audit_logs_action on audit_logs(action);
create index if not exists idx_audit_logs_created on audit_logs(created_at desc);

alter table audit_logs enable row level security;

create policy "Service role only audit logs" on audit_logs
  for all using (auth.role() = 'service_role');

-- ─── PERFORMANCE INDEXES ─────────────────────────────────
create index if not exists idx_missions_status on missions(status);
create index if not exists idx_missions_city on missions(city);
create index if not exists idx_missions_deadline on missions(deadline);
create index if not exists idx_mission_claims_wallet on mission_claims(agent_wallet);
create index if not exists idx_mission_claims_status on mission_claims(status);
create index if not exists idx_agent_profiles_wallet on agent_profiles(wallet_address);
create index if not exists idx_brands_status on brands(status);
create index if not exists idx_users_wallet on users(wallet_address);
create index if not exists idx_users_kyc on users(kyc_status);
create index if not exists idx_marketplace_status on marketplace_listings(status);
create index if not exists idx_marketplace_brand on marketplace_listings(brand_id);
create index if not exists idx_governance_status on governance_proposals(status);
create index if not exists idx_votes_proposal on votes(proposal_id);

-- ─── FIX TRANSACTIONS TABLE ──────────────────────────────
alter table transactions
  add column if not exists user_wallet text,
  add column if not exists type text,
  add column if not exists tx_hash text;

create index if not exists idx_transactions_wallet on transactions(user_wallet);
create index if not exists idx_transactions_created on transactions(created_at desc);

-- ─── KYC ENCRYPTION COLUMNS ──────────────────────────────
alter table users
  add column if not exists encrypted_email text,
  add column if not exists encrypted_full_name text,
  add column if not exists encrypted_id_number text,
  add column if not exists kyc_provider text,
  add column if not exists kyc_verified_at timestamp,
  add column if not exists risk_score integer default 0,
  add column if not exists is_blocked boolean default false,
  add column if not exists block_reason text;

create index if not exists idx_users_blocked on users(is_blocked);
create index if not exists idx_users_risk on users(risk_score desc);

-- ─── SUSPICIOUS ACTIVITY TABLE ───────────────────────────
create table if not exists suspicious_activity (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp default now(),
  wallet_address text not null,
  activity_type text not null,
  details jsonb,
  resolved boolean default false,
  resolved_at timestamp,
  resolved_by text
);

alter table suspicious_activity enable row level security;

create policy "Service role only suspicious" on suspicious_activity
  for all using (auth.role() = 'service_role');

create index if not exists idx_suspicious_wallet on suspicious_activity(wallet_address);
create index if not exists idx_suspicious_resolved on suspicious_activity(resolved);

-- ─── REFRESH SCHEMA ──────────────────────────────────────
notify pgrst, 'reload schema';
