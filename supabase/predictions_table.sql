-- ============================================================
--  Sokastar — Predictions Table Schema
--  Run this once in your Supabase SQL Editor:
--    https://app.supabase.com → Project → SQL Editor
-- ============================================================

create table if not exists public.predictions (
  id           bigint       primary key,   -- epoch ms set by server
  home_team    text         not null,
  away_team    text         not null,
  league       text,
  match_date   date,
  match_time   text,
  pick         text,
  odds         numeric(6,2),
  tier         text         not null default 'free'    check (tier in ('free','premium','vip')),
  status       text         not null default 'pending' check (status in ('pending','live','won','lost','void')),
  score        text,
  notes        text,
  created_at   timestamptz  default now(),
  updated_at   timestamptz  default now()
);

-- Index for fast date-based queries (daily tips)
create index if not exists idx_predictions_date   on public.predictions (match_date);
create index if not exists idx_predictions_status on public.predictions (status);
create index if not exists idx_predictions_tier   on public.predictions (tier);

-- Row-Level Security: allow all authenticated reads, restrict writes to service_role
alter table public.predictions enable row level security;

-- Policy: Anyone can read predictions (public website)
create policy "Public can read predictions"
  on public.predictions for select
  using (true);

-- Policy: Only service role can write (server.js uses the service-role key via @supabase/supabase-js)
-- This is handled automatically when you use the SERVICE_ROLE_KEY in your .env
