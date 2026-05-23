-- PostgreSQL Migration: Zero-Knowledge Schema Additions
-- Run this migration for PostgreSQL deployments

-- Add encrypted_blob column to orders for ZK storage
ALTER TABLE orders ADD COLUMN IF NOT EXISTS encrypted_blob BYTEA;

-- Add status column to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';

-- Add disputed_at column to orders
ALTER TABLE orders ADD COLUMN IF NOT EXISTS disputed_at TIMESTAMP;

-- Add evidence table for disputes
CREATE TABLE IF NOT EXISTS dispute_evidence (
    id BYTEA PRIMARY KEY,
    order_id BYTEA NOT NULL REFERENCES orders(id),
    submitted_by BYTEA NOT NULL,
    encrypted_evidence BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dispute_evidence_order ON dispute_evidence(order_id);

-- Add payment confirmations tracking
CREATE TABLE IF NOT EXISTS payment_confirmations (
    id BYTEA PRIMARY KEY,
    order_id BYTEA NOT NULL REFERENCES orders(id),
    currency VARCHAR(10) NOT NULL,
    tx_hash VARCHAR(100) NOT NULL,
    confirmations INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_confirmations_order ON payment_confirmations(order_id);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
ALTER TABLE orders ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT NOW();

-- Note: Triggers need to be created per-table in PostgreSQL
-- This is handled by the application code for now