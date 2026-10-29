create table public.profiles (
  id uuid primary key,
  email text not null,
  role text not null default 'member'
);

create table public.invoices (
  id uuid primary key,
  org_id uuid not null,
  amount numeric not null
);
alter table public.invoices enable row level security;

create policy "anyone can insert invoices" on public.invoices
  for insert with check (true);
