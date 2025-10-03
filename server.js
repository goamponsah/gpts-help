// ---- Robust, idempotent schema setup ----
async function ensureSchema() {
  // 1) Create tables if missing
  await pool.query(`
    create table if not exists users (
      id            bigserial primary key,
      email         text not null unique,
      pass_salt     text,
      pass_hash     text,
      plan          text not null default 'FREE',
      created_at    timestamptz not null default now(),
      updated_at    timestamptz not null default now()
    );

    create table if not exists conversations (
      id            bigserial primary key,
      user_id       bigint,
      title         text not null,
      archived      boolean not null default false,
      created_at    timestamptz not null default now(),
      updated_at    timestamptz not null default now()
    );

    create table if not exists messages (
      id            bigserial primary key,
      conversation_id bigint,
      role          text,
      content       text,
      created_at    timestamptz not null default now()
    );

    create table if not exists share_links (
      id               bigserial primary key,
      conversation_id  bigint,
      token            text not null unique,
      revoked          boolean not null default false,
      created_at       timestamptz not null default now()
    );

    create table if not exists paystack_receipts (
      id            bigserial primary key,
      email         text,
      reference     text not null unique,
      plan_code     text,
      status        text,
      raw           jsonb,
      created_at    timestamptz not null default now()
    );

    create table if not exists password_resets (
      id            bigserial primary key,
      user_id       bigint,
      token_hash    text not null,
      expires_at    timestamptz not null,
      used          boolean not null default false,
      created_at    timestamptz not null default now()
    );
  `);

  // 2) Add any missing columns on legacy tables
  await pool.query(`
    alter table if exists conversations
      add column if not exists user_id    bigint,
      add column if not exists title      text not null default 'New chat',
      add column if not exists archived   boolean not null default false,
      add column if not exists created_at timestamptz not null default now(),
      add column if not exists updated_at timestamptz not null default now();

    alter table if exists messages
      add column if not exists conversation_id bigint,
      add column if not exists role           text,
      add column if not exists content        text,
      add column if not exists created_at     timestamptz not null default now();

    alter table if exists share_links
      add column if not exists conversation_id bigint,
      add column if not exists token           text,
      add column if not exists revoked         boolean not null default false,
      add column if not exists created_at      timestamptz not null default now();

    alter table if exists password_resets
      add column if not exists user_id    bigint,
      add column if not exists token_hash text,
      add column if not exists expires_at timestamptz,
      add column if not exists used       boolean not null default false,
      add column if not exists created_at timestamptz not null default now();
  `);

  // 2a) Very old DBs may lack users.id → create and backfill
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'users' AND column_name = 'id'
      ) THEN
        CREATE SEQUENCE IF NOT EXISTS users_id_seq;
        ALTER TABLE users ADD COLUMN id bigint;
        ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq'::regclass);
        UPDATE users SET id = nextval('users_id_seq'::regclass) WHERE id IS NULL;
      END IF;
    END $$;
  `);

  // 2b) Ensure PRIMARY KEY on users.id if missing (no duplicate errors)
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'users'::regclass AND contype = 'p'
      ) THEN
        BEGIN
          ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
        EXCEPTION WHEN duplicate_object THEN
          -- If something else created it, ignore
          NULL;
        END;
      END IF;
    END $$;
  `);

  // 3) Foreign keys (safe on duplicates)
  await pool.query(`
    DO $$ BEGIN
      ALTER TABLE conversations
        ADD CONSTRAINT conversations_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE messages
        ADD CONSTRAINT messages_conversation_fk
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE share_links
        ADD CONSTRAINT share_links_conversation_fk
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      ALTER TABLE password_resets
        ADD CONSTRAINT password_resets_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
  `);

  // 4) Indexes
  await pool.query(`
    create index if not exists conversations_user_idx
      on conversations(user_id, created_at desc);
    create index if not exists messages_conv_idx
      on messages(conversation_id, id);
    create index if not exists password_resets_token_idx
      on password_resets(token_hash);
  `);
}
