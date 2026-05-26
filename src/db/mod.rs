use anyhow::Result;
use sqlx::{sqlite::SqlitePool, Row};

pub mod models;

/// Initialize a SQLite database pool
pub async fn init_sqlite_pool(db_path: &str) -> Result<SqlitePool> {
    let pool = SqlitePool::connect(db_path).await?;
    Ok(pool)
}

/// Run SQLite migrations with version tracking
/// SECURITY: Tracks applied migrations for safe updates
pub async fn run_sqlite_migrations(pool: &SqlitePool) -> Result<()> {
    // Create schema_migrations table first (for tracking)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            description TEXT
        )"
    ).execute(pool).await?;

    // Get current schema version
    let current_version: Option<(i64,)> = sqlx::query_as(
        "SELECT MAX(version) FROM schema_migrations"
    )
    .fetch_optional(pool)
    .await?;

    let db_version = current_version.map(|v| v.0).unwrap_or(0);

    // Run migrations based on version
    if db_version < 1 {
        run_migration_v1(pool).await?;
    }
    if db_version < 2 {
        run_migration_v2(pool).await?;
    }
    if db_version < 3 {
        run_migration_v3(pool).await?;
    }
    if db_version < 4 {
        run_migration_v4(pool).await?;
    }
    if db_version < 5 {
        run_migration_v5(pool).await?;
    }
    if db_version < 6 {
        run_migration_v6(pool).await?;
    }
    if db_version < 7 {
        run_migration_v7(pool).await?;
    }
    if db_version < 8 {
        run_migration_v8(pool).await?;
    }
    if db_version < 9 {
        run_migration_v9(pool).await?;
    }
    if db_version < 10 {
        run_migration_v10(pool).await?;
    }
    if db_version < 11 {
        run_migration_v11(pool).await?;
    }
    if db_version < 12 {
        run_migration_v12(pool).await?;
    }

    Ok(())
}

async fn run_migration_v1(pool: &SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Create users table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            pubkey_hash BLOB PRIMARY KEY,
            encrypted_meta BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            last_active INTEGER NOT NULL,
            status TEXT DEFAULT 'active'
        )"
    ).execute(pool).await?;
    
    // Create listings table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS listings (
            id BLOB PRIMARY KEY,
            seller_pubkey_hash BLOB NOT NULL,
            seller_pubkey TEXT,
            encrypted_data BLOB NOT NULL,
            encrypted_search BLOB,
            currency TEXT NOT NULL DEFAULT 'XMR',
            price_amount TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            updated_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;
    
    // Create orders table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS orders (
            id BLOB PRIMARY KEY,
            listing_id BLOB NOT NULL,
            buyer_pubkey_hash BLOB NOT NULL,
            seller_pubkey_hash BLOB NOT NULL,
            buyer_pubkey TEXT,
            seller_pubkey TEXT,
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
            disputed_at INTEGER,
            expires_at INTEGER,
            encrypted_blob BLOB
        )"
    ).execute(pool).await?;
    
    // Create chat_messages table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS chat_messages (
            id BLOB PRIMARY KEY,
            order_id BLOB NOT NULL,
            sender_pubkey_hash BLOB NOT NULL,
            encrypted_body BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;
    
    // Create indexes for V1
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings(seller_pubkey_hash)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_pubkey_hash)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_pubkey_hash)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_state ON orders(state)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_chat_order ON chat_messages(order_id)").execute(pool).await?;

    // Record migration
    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(1i64)
    .bind(now)
    .bind("Initial schema with users, listings, orders, chat_messages")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v2(pool: &SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Create audit_logs table for security events
    // SECURITY: Comprehensive audit trail for all security-sensitive operations
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            pubkey_hash TEXT,
            resource_id TEXT,
            resource_type TEXT,
            details TEXT,
            timestamp INTEGER NOT NULL,
            severity TEXT NOT NULL,
            ip_hash TEXT,
            user_agent TEXT
        )"
    ).execute(pool).await?;
    
    // Create payment_audits table for rollback tracking
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS payment_audits (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            tx_hash TEXT NOT NULL,
            address TEXT NOT NULL,
            amount INTEGER NOT NULL,
            credited_height INTEGER,
            credited_at INTEGER NOT NULL,
            verified INTEGER DEFAULT 0,
            rollback_at INTEGER,
            created_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;

    // Create additional indexes for V2
    // SECURITY: Index on escrow_address for payment verification performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_escrow ON orders(escrow_address)").execute(pool).await?;
    
    // SECURITY: Index on encrypted_search for search performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_listings_search ON listings(encrypted_search)").execute(pool).await?;
    
    // SECURITY: Index on audit_logs timestamp for querying
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)").execute(pool).await?;
    
    // SECURITY: Index on audit_logs event_type for filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type)").execute(pool).await?;
    
    // SECURITY: Index on payment_audits for verification queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_payment_audit_tx ON payment_audits(tx_hash)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_payment_audit_order ON payment_audits(order_id)").execute(pool).await?;
    
    // Index on listing expiry for cleanup jobs
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_listings_expires ON listings(expires_at)").execute(pool).await?;

    // Record migration
    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(2i64)
    .bind(now)
    .bind("Added audit_logs, payment_audits tables and additional indexes")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v3(pool: &SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS disputes (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL UNIQUE,
            opened_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            resolution TEXT,
            resolved_by TEXT,
            resolved_at INTEGER,
            created_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dispute_evidence (
            id TEXT PRIMARY KEY,
            dispute_id TEXT NOT NULL,
            submitted_by TEXT NOT NULL,
            encrypted_content BLOB NOT NULL,
            content_type TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_disputes_order ON disputes(order_id)").execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_dispute_evidence_dispute ON dispute_evidence(dispute_id)").execute(pool).await?;

    if !column_exists(pool, "orders", "disputed_at").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN disputed_at INTEGER")
            .execute(pool)
            .await
        {
            tracing::warn!("Migration: could not add disputed_at column: {e}");
        }
    }

    if !column_exists(pool, "orders", "dispute_id").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN dispute_id TEXT")
            .execute(pool)
            .await
        {
            tracing::warn!("Migration: could not add dispute_id column: {e}");
        }
    }

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(3i64)
    .bind(now)
    .bind("Added disputes, dispute_evidence tables, dispute_id and disputed_at on orders")
    .execute(pool)
    .await?;

    Ok(())
}

/// Get current schema version
pub async fn get_schema_version(pool: &SqlitePool) -> Result<i64> {
    let result: Option<(i64,)> = sqlx::query_as(
        "SELECT MAX(version) FROM schema_migrations"
    )
    .fetch_optional(pool)
    .await?;
    
    Ok(result.map(|v| v.0).unwrap_or(0))
}

/// Check if a column exists in a SQLite table.
async fn column_exists(pool: &sqlx::SqlitePool, table: &str, column: &str) -> bool {
    let sql = format!("PRAGMA table_info({table})");
    match sqlx::query(&sql).fetch_all(pool).await {
        Ok(rows) => {
            rows.iter().any(|row| {
                row.try_get::<String, _>(1).ok().as_deref() == Some(column)
            })
        }
        Err(e) => {
            tracing::warn!("Failed to check column existence for {table}.{column}: {e}");
            false
        }
    }
}

async fn run_migration_v4(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    if !column_exists(pool, "orders", "owner_pubkey").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN owner_pubkey TEXT")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add owner_pubkey column: {e}");
        }
    }

    if !column_exists(pool, "orders", "fee_percent").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN fee_percent INTEGER")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add fee_percent column: {e}");
        }
    }

    if !column_exists(pool, "orders", "fee_address").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN fee_address TEXT")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add fee_address column: {e}");
        }
    }

    if !column_exists(pool, "orders", "multi_sig_key").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN multi_sig_key BLOB")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add multi_sig_key column: {e}");
        }
    }

    if !column_exists(pool, "orders", "multi_sig_redeem_script").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN multi_sig_redeem_script TEXT")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add multi_sig_redeem_script column: {e}");
        }
    }

    if !column_exists(pool, "orders", "buyer_sig").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN buyer_sig BLOB")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add buyer_sig column: {e}");
        }
    }

    if !column_exists(pool, "orders", "seller_sig").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN seller_sig BLOB")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add seller_sig column: {e}");
        }
    }

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(4i64)
    .bind(now)
    .bind("Added escrow/multi-sig columns: owner_pubkey, fee_percent, fee_address, multi_sig_key, multi_sig_redeem_script, buyer_sig, seller_sig")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v5(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    if !column_exists(pool, "orders", "updated_at").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN updated_at INTEGER")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add updated_at column: {e}");
        }
    }

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(5i64)
    .bind(now)
    .bind("Added updated_at column to orders for state transition timestamps")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v6(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Drop tables that store identifying metadata
    sqlx::query("DROP TABLE IF EXISTS audit_logs")
        .execute(pool).await?;

    sqlx::query("DROP TABLE IF EXISTS payment_audits")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(6i64)
    .bind(now)
    .bind("Dropped audit_logs and payment_audits tables (anti-anonymity metadata)")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v7(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Drop users table — auth is now stateless (HMAC-derived, no DB reads)
    sqlx::query("DROP TABLE IF EXISTS users")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(7i64)
    .bind(now)
    .bind("Dropped users table (stateless HMAC auth — no DB writes on register)")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v8(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    sqlx::query("DROP TABLE IF EXISTS chat_messages")
        .execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS disputes")
        .execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS dispute_evidence")
        .execute(pool).await?;

    sqlx::query("DROP INDEX IF EXISTS idx_chat_order")
        .execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_disputes_order")
        .execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_dispute_evidence_dispute")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(8i64)
    .bind(now)
    .bind("Dropped chat_messages, disputes, dispute_evidence tables")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v9(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    if !column_exists(pool, "orders", "encrypted_order_blob").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN encrypted_order_blob BLOB")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add encrypted_order_blob column: {e}");
        }
    }

    if !column_exists(pool, "orders", "day_bucket").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN day_bucket INTEGER")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add day_bucket column: {e}");
        }
    }

    if !column_exists(pool, "orders", "expiry_bucket").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN expiry_bucket INTEGER")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add expiry_bucket column: {e}");
        }
    }

    sqlx::query("DROP INDEX IF EXISTS idx_orders_buyer")
        .execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_orders_seller")
        .execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_orders_state")
        .execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_orders_escrow")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_day_bucket ON orders(day_bucket)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_expiry_bucket ON orders(expiry_bucket)")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(9i64)
    .bind(now)
    .bind("Added encrypted_order_blob, day_bucket, expiry_bucket to orders; new indexes")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v10(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Rebuild orders table with only the 4 currently-used columns.
    // This drops 28+ legacy columns (V1-V5 schema) that are no longer queried.
    // Using CREATE + DROP + RENAME for efficiency (single table rebuild vs 28 ALTER TABLEs).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS orders_new (
            id BLOB PRIMARY KEY,
            encrypted_order_blob BLOB,
            day_bucket INTEGER,
            expiry_bucket INTEGER
        )"
    ).execute(pool).await?;

    sqlx::query(
        "INSERT INTO orders_new (id, encrypted_order_blob, day_bucket, expiry_bucket)
         SELECT id, encrypted_order_blob, day_bucket, expiry_bucket FROM orders"
    ).execute(pool).await?;

    sqlx::query("DROP TABLE orders").execute(pool).await?;
    sqlx::query("ALTER TABLE orders_new RENAME TO orders").execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_day_bucket ON orders(day_bucket)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_orders_expiry_bucket ON orders(expiry_bucket)")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(10i64)
    .bind(now)
    .bind("Dropped legacy columns from orders (kept: id, encrypted_order_blob, day_bucket, expiry_bucket)")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v11(pool: &sqlx::SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    // Rebuild listings table with oblivious blob columns.
    // Drops 11 legacy plaintext columns (seller_pubkey_hash, seller_pubkey,
    // encrypted_data, encrypted_search, currency, price_amount, status,
    // created_at, expires_at, updated_at).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS listings_new (
            id BLOB PRIMARY KEY,
            encrypted_listing_blob BLOB NOT NULL DEFAULT x'',
            day_bucket INTEGER NOT NULL DEFAULT 0,
            search_token BLOB
        )"
    ).execute(pool).await?;

    // Migrate existing rows with empty blob as placeholder
    // (existing listings become unreadable until re-created by the app)
    sqlx::query(
        "INSERT INTO listings_new (id, encrypted_listing_blob, day_bucket, search_token)
         SELECT id, x'', 0, encrypted_search FROM listings"
    ).execute(pool).await?;

    // Drop old indexes that reference dropped columns
    sqlx::query("DROP INDEX IF EXISTS idx_listings_seller").execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_listings_status").execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_listings_search").execute(pool).await?;
    sqlx::query("DROP INDEX IF EXISTS idx_listings_expires").execute(pool).await?;

    sqlx::query("DROP TABLE listings").execute(pool).await?;
    sqlx::query("ALTER TABLE listings_new RENAME TO listings").execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_listings_day_bucket ON listings(day_bucket)")
        .execute(pool).await?;

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(11i64)
    .bind(now)
    .bind("Rebuilt listings table: encrypted_listing_blob, day_bucket, search_token (dropped 11 plaintext columns)")
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_migration_v12(pool: &SqlitePool) -> Result<()> {
    let now = crate::crypto::zk::floor_timestamp_6h(time::OffsetDateTime::now_utc().unix_timestamp());

    if !column_exists(pool, "orders", "version").await {
        if let Err(e) = sqlx::query("ALTER TABLE orders ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
            .execute(pool).await
        {
            tracing::warn!("Migration: could not add version column: {e}");
        }
    }

    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)"
    )
    .bind(12i64)
    .bind(now)
    .bind("Added version column to orders for TOCTOU guard on concurrent writes")
    .execute(pool)
    .await?;

    Ok(())
}

/// PostgreSQL support - to be implemented
#[allow(dead_code)]
pub async fn init_postgres_pool(_database_url: &str) -> Result<SqlitePool> {
    Err(anyhow::anyhow!("PostgreSQL support coming soon - use SQLite for now"))
}