-- Add full pubkey columns for E2E encryption
ALTER TABLE listings ADD COLUMN seller_pubkey TEXT;
ALTER TABLE orders ADD COLUMN buyer_pubkey TEXT;
ALTER TABLE orders ADD COLUMN seller_pubkey TEXT;