-- Corre esto UNA VEZ en el SQL editor de tu proyecto de Supabase
-- (Project → SQL Editor → New query → pegar y ejecutar).

create extension if not exists "pgcrypto";

create table if not exists analyses (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  channel         text not null default 'dashboard',   -- 'dashboard' | 'whatsapp'
  from_number     text,                                  -- número de WhatsApp, si aplica
  message_text    text not null,
  risk_score      int not null,
  risk_level      text not null,                         -- 'bajo' | 'medio' | 'alto'
  blocked         boolean not null,
  forwarded       boolean not null,
  matches         jsonb not null default '[]'::jsonb,
  claude_text     text,
  claude_stub     boolean,
  bot_response    text
);

create index if not exists analyses_created_at_idx on analyses (created_at desc);
create index if not exists analyses_channel_idx on analyses (channel);
create index if not exists analyses_blocked_idx on analyses (blocked);
create index if not exists analyses_risk_level_idx on analyses (risk_level);

-- Habilita Realtime para esta tabla si más adelante quieres que el
-- dashboard se actualice solo, sin refrescar manualmente:
--   Project → Database → Replication → activa "analyses".

-- RLS: déjala activada y SIN policies de lectura/escritura pública.
-- El backend escribe usando la service_role key (que ignora RLS por
-- diseño de Supabase), nunca expongas esa key al frontend.
alter table analyses enable row level security;
