-- ============================================================
--  Sokastar — Admin Settings Table Schema
--  Run this once in your Supabase SQL Editor:
--    https://app.supabase.com → Project → SQL Editor
-- ============================================================

create table if not exists public.admin_settings (
  key         text         primary key,
  value       text         not null,
  updated_at  timestamptz  default now()
);

-- Enable RLS
alter table public.admin_settings enable row level security;

-- Policy: Only service role can read/write admin settings
-- (server.js uses the SUPABASE_KEY service-role client)
create policy "Service role has full access to admin_settings"
  on public.admin_settings
  for all
  using (true)
  with check (true);
