use blake3;

pub fn hash_pubkey(pubkey_bytes: &[u8]) -> [u8; 32] {
    blake3::hash(pubkey_bytes).into()
}

pub fn hash_search_keyword(keyword: &str, domain_secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"marketplace_search_v1");
    hasher.update(domain_secret);
    hasher.update(keyword.as_bytes());
    hasher.finalize().into()
}

pub fn hash_challenge(challenge: &[u8], server_secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"marketplace_challenge_v1");
    hasher.update(server_secret);
    hasher.update(challenge);
    hasher.finalize().into()
}
