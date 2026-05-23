use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Order {
    pub id: Vec<u8>,
    pub encrypted_order_blob: Vec<u8>,
    pub day_bucket: i64,
    pub expiry_bucket: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderData {
    pub listing_id: Vec<u8>,
    pub buyer_pubkey_hash: Vec<u8>,
    pub seller_pubkey_hash: Vec<u8>,
    pub buyer_pubkey: Option<String>,
    pub seller_pubkey: Option<String>,
    pub state: String,
    pub currency: String,
    pub escrow_address: Option<String>,
    pub escrow_amount: Option<String>,
    pub time_lock_seconds: i64,
    pub created_at: i64,
    pub funded_at: Option<i64>,
    pub shipped_at: Option<i64>,
    pub confirmed_at: Option<i64>,
    pub released_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub disputed_at: Option<i64>,
    pub dispute_id: Option<String>,
    pub owner_pubkey: Option<String>,
    pub fee_percent: Option<i64>,
    pub fee_address: Option<String>,
    pub dispute: Option<DisputeData>,
    pub chat_messages: Vec<ChatMessageData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeData {
    pub id: String,
    pub opened_by: String,
    pub reason: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<i64>,
    pub created_at: i64,
    pub evidence: Vec<DisputeEvidenceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeEvidenceEntry {
    pub id: String,
    pub submitted_by: String,
    pub encrypted_content: Vec<u8>,
    pub content_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageData {
    pub id: Vec<u8>,
    pub sender_pubkey_hash: Vec<u8>,
    pub encrypted_body: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Listing {
    pub id: Vec<u8>,
    pub encrypted_listing_blob: Vec<u8>,
    pub day_bucket: i64,
    pub search_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingData {
    pub seller_pubkey_hash: Vec<u8>,
    pub seller_pubkey: Option<String>,
    pub encrypted_data: Vec<u8>,
    pub encrypted_search: Option<Vec<u8>>,
    pub currency: String,
    pub price_amount: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updated_at: i64,
}

impl OrderData {
    pub fn state_transitions(&self) -> Vec<&'static str> {
        match self.state.as_str() {
            "pending" => vec!["cancelled", "funded"],
            "funded" => vec!["shipped", "disputed"],
            "shipped" => vec!["confirmed", "disputed", "released"],
            "confirmed" => vec!["released"],
            "disputed" => vec!["released", "refunded"],
            _ => vec![],
        }
    }

    pub fn can_transition_to(&self, new_state: &str) -> bool {
        self.state_transitions().contains(&new_state)
    }
}

impl Listing {
    pub fn new_id() -> Vec<u8> {
        Uuid::new_v4().as_bytes().to_vec()
    }
}

impl Order {
    pub fn new_id() -> Vec<u8> {
        Uuid::new_v4().as_bytes().to_vec()
    }
}

impl ChatMessageData {
    pub fn new_id() -> Vec<u8> {
        Uuid::new_v4().as_bytes().to_vec()
    }
}

impl DisputeData {
    pub fn new_id() -> String {
        Uuid::new_v4().to_string()
    }
}

impl DisputeEvidenceEntry {
    pub fn new_id() -> String {
        Uuid::new_v4().to_string()
    }
}
