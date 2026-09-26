-- PLANTED FLAW (Phase 3, Supabase): table created, RLS never enabled anywhere.
-- RLS is OFF by default on a new table, so this is silently wide open.
create table orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total numeric not null
);

-- PLANTED FLAW: RLS turned on, then explicitly turned back off.
create table profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  bio text
);
alter table profiles enable row level security;
alter table profiles disable row level security;

-- PLANTED FLAW: a policy that grants access to everyone, the same bug as
-- Firebase's "allow: if true".
create table payments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  amount numeric not null
);
alter table payments enable row level security;
create policy "public read" on payments
  for select
  using (true);
