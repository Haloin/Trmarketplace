CREATE TABLE IF NOT EXISTS users (
    pubkey_hash BLOB PRIMARY KEY NOT NULL,
    encrypted_meta BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_active INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS listings (
    id BLOB PRIMARY KEY NOT NULL,
    seller_pubkey_hash BLOB NOT NULL REFERENCES users(pubkey_hash),
    encrypted_data BLOB NOT NULL,
    encrypted_search BLOB,
    currency TEXT NOT NULL DEFAULT 'XMR',
    price_amount TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings(seller_pubkey_hash);
CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);

CREATE TABLE IF NOT EXISTS orders (
    id BLOB PRIMARY KEY NOT NULL,
    listing_id BLOB NOT NULL REFERENCES listings(id),
    buyer_pubkey_hash BLOB NOT NULL REFERENCES users(pubkey_hash),
    seller_pubkey_hash BLOB NOT NULL REFERENCES users(pubkey_hash),
    state TEXT NOT NULL DEFAULT 'pending',
    currency TEXT NOT NULL,
    escrow_address TEXT,
    escrow_amount TEXT,
    time_lock_seconds INTEGER NOT NULL DEFAULT 604800,
    created_at INTEGER NOT NULL,
    funded_at INTEGER,
    shipped_at INTEGER,
    confirmed_at INTEGER,
    released_at INTEGER,
    refunded_at INTEGER,
    expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_pubkey_hash);
CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_pubkey_hash);
CREATE INDEX IF NOT EXISTS idx_orders_state ON orders(state);

CREATE TABLE IF NOT EXISTS chat_messages (
    id BLOB PRIMARY KEY NOT NULL,
    order_id BLOB NOT NULL REFERENCES orders(id),
    sender_pubkey_hash BLOB NOT NULL,
    encrypted_body BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_order ON chat_messages(order_id);
