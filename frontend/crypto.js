// Client-side crypto using tweetnacl
// Provides Ed25519 key generation, signing, and E2E encryption
// With password-derived key wrapping (PBKDF2 + XSalsa20-Poly1305)

const CRYPTO = (() => {
  let keypair = null;
  let hasWrappedKey = false;

  // IndexedDB wrapper for secure key storage
  const DB_NAME = 'tor_marketplace_keys';
  const STORE_NAME = 'keyvault';
  const LISTING_KEYS_STORE = 'listing_keys';
  const DB_VERSION = 2;

  function openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(LISTING_KEYS_STORE)) {
          db.createObjectStore(LISTING_KEYS_STORE, { keyPath: 'id' });
        }
      };
    });
  }

  async function dbGet(key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(key);
      request.onsuccess = () => resolve(request.result?.value);
      request.onerror = () => reject(request.error);
    });
  }

  async function dbPut(key, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.put({ id: key, value });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async function dbDelete(key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(key);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async function dbGetAllListingKeys() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(LISTING_KEYS_STORE, 'readonly');
      const store = tx.objectStore(LISTING_KEYS_STORE);
      const request = store.getAll();
      request.onsuccess = () => {
        const result = {};
        request.result.forEach(item => { result[item.id] = item.value; });
        resolve(result);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async function dbPutListingKey(listingId, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(LISTING_KEYS_STORE, 'readwrite');
      const store = tx.objectStore(LISTING_KEYS_STORE);
      const request = store.put({ id: listingId, value: key });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // PBKDF2 key derivation (using Web Crypto API)
  async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Wrap (encrypt) the secret key
  async function wrapKey(seckey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      seckey
    );
    
    // Format: salt (16) + iv (12) + encrypted
    const result = new Uint8Array(16 + 12 + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, 16);
    result.set(new Uint8Array(encrypted), 28);
    
    return u8ToBase64(result);
  }

  // Unwrap (decrypt) the secret key
  async function unwrapKey(wrappedBase64, password) {
    try {
      const data = base64ToU8(wrappedBase64);
      const salt = data.slice(0, 16);
      const iv = data.slice(16, 28);
      const encrypted = data.slice(28);
      
      const key = await deriveKey(password, salt);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encrypted
      );
      
      return new Uint8Array(decrypted);
    } catch (e) {
      return null; // Wrong password or corrupted data
    }
  }

  // Check if wrapped key exists in IndexedDB
  async function hasStoredKey() {
    try {
      const wrapped = await dbGet('wrapped_key');
      hasWrappedKey = !!wrapped;
      return hasWrappedKey;
    } catch (e) {
      return false;
    }
  }

  // Unlock with password
  async function unlockWithPassword(password) {
    if (!password || password.length < 12) {
      throw new Error('Password must be at least 12 characters');
    }
    
    const wrapped = await dbGet('wrapped_key');
    if (!wrapped) {
      throw new Error('No stored key found');
    }
    
    const seckey = await unwrapKey(wrapped, password);
    if (!seckey) {
      throw new Error('Invalid password');
    }
    
    const pubkey = await dbGet('pubkey');
    if (!pubkey) {
      throw new Error('Public key not found');
    }
    
    keypair = {
      pubkey: base64ToU8(pubkey),
      seckey: seckey
    };
    
    // Secure memory: overwrite the password in memory would require
    // explicit cleanup (not possible in JS, but we've minimized exposure)
    return keypair;
  }

  // Create new keypair with password
  async function createKeypairWithPassword(password) {
    if (!password || password.length < 12) {
      throw new Error('Password must be at least 12 characters');
    }
    
    // Generate new Ed25519 keypair
    const kp = nacl.sign.keyPair();
    keypair = {
      pubkey: kp.publicKey,
      seckey: kp.secretKey
    };
    
    // Wrap the secret key with the password
    const wrapped = await wrapKey(kp.secretKey, password);
    
    // Store in IndexedDB
    await dbPut('wrapped_key', wrapped);
    await dbPut('pubkey', u8ToBase64(kp.publicKey));
    await dbPut('created_at', Date.now());
    
    hasWrappedKey = true;
    
    return keypair;
  }

  // Load keypair (legacy localStorage support for migration)
  function loadKeypair() {
    const stored = localStorage.getItem('tm_keypair');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        keypair = {
          pubkey: base64ToU8(parsed.pubkey),
          seckey: base64ToU8(parsed.seckey)
        };
        return keypair;
      } catch(e) {
        localStorage.removeItem('tm_keypair');
      }
    }
    return null;
  }

  // Generate new keypair (legacy - requires password now)
  async function generateKeypair(password) {
    if (password) {
      return await createKeypairWithPassword(password);
    }
    throw new Error('Password required to generate keypair');
  }

  // Check if user has a stored key
  function hasWrappedKeySync() {
    return hasWrappedKey;
  }

  function getPubkey() {
    return keypair ? keypair.pubkey : null;
  }

  function getSecretKey() {
    return keypair ? keypair.seckey : null;
  }

  function getPubkeyHex() {
    const pk = getPubkey();
    return pk ? u8ToHex(pk) : null;
  }

  function sign(msgHex) {
    if (!keypair) return null;
    const msg = hexToU8(msgHex);
    const sig = nacl.sign.detached(msg, keypair.seckey);
    return u8ToHex(sig);
  }

  // Generate deterministic encryption key for order-specific E2E
  function deriveOrderKey(orderId, counterpartyPubkey) {
    if (!keypair) return null;
    const shared = nacl.box.before(
      typeof counterpartyPubkey === 'string' ? hexToU8(counterpartyPubkey) : counterpartyPubkey,
      keypair.seckey
    );
    const orderKey = nacl.hash(new Uint8Array([...shared, ...(typeof orderId === 'string' ? hexToU8(orderId) : orderId)]));
    return u8ToHex(orderKey.slice(0, 32));
  }

  function encryptForOrder(orderId, counterpartyPubkey, plaintext) {
    const keyHex = deriveOrderKey(orderId, counterpartyPubkey);
    if (!keyHex) return null;
    const key = hexToU8(keyHex);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(
      new TextEncoder().encode(plaintext),
      nonce,
      key
    );
    if (!encrypted) return null;
    return u8ToHex(new Uint8Array([...nonce, ...encrypted]));
  }

  function decryptForOrder(orderId, counterpartyPubkey, ciphertextHex) {
    const keyHex = deriveOrderKey(orderId, counterpartyPubkey);
    if (!keyHex) return null;
    const key = hexToU8(keyHex);
    const data = hexToU8(ciphertextHex);
    const nonce = data.slice(0, 24);
    const encrypted = data.slice(24);
    const decrypted = nacl.secretbox.open(encrypted, nonce, key);
    if (!decrypted) return null;
    return new TextDecoder().decode(decrypted);
  }

  function hashPubkey(pubkeyHex) {
    const pk = hexToU8(pubkeyHex);
    const h = nacl.hash(pk);
    return u8ToHex(h.slice(0, 32));
  }

  // Encryption for listing metadata
  function encryptListingData(title, desc, price, key) {
    const plaintext = JSON.stringify({ title, desc, price });
    if (!key) key = nacl.randomBytes(32);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(
      new TextEncoder().encode(plaintext),
      nonce,
      key
    );
    if (!encrypted) return null;
    return {
      encrypted: u8ToHex(new Uint8Array([...nonce, ...encrypted])),
      key: u8ToHex(key)
    };
  }

  function decryptListingData(encryptedHex, keyHex) {
    const key = hexToU8(keyHex);
    const data = hexToU8(encryptedHex);
    const nonce = data.slice(0, 24);
    const encrypted = data.slice(24);
    const decrypted = nacl.secretbox.open(encrypted, nonce, key);
    if (!decrypted) return null;
    try {
      return JSON.parse(new TextDecoder().decode(decrypted));
    } catch(e) {
      return null;
    }
  }

  // Clear all stored keys (logout)
  async function clearKeys() {
    keypair = null;
    hasWrappedKey = false;
    await dbDelete('wrapped_key');
    await dbDelete('pubkey');
    await dbDelete('created_at');
    localStorage.removeItem('tm_keypair');
  }

  // Listing key management (stored in IndexedDB)
  async function getAllListingKeys() {
    return await dbGetAllListingKeys();
  }

  async function saveListingKey(listingId, keyHex) {
    await dbPutListingKey(listingId, keyHex);
  }

  // Hex/Base64 utilities
  function u8ToHex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToU8(hex) {
    const len = hex.length / 2;
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buf;
  }

  function u8ToBase64(buf) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    for (let i = 0; i < buf.length; i += 3) {
      const b = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2];
      result += chars[(b >> 18) & 63] + chars[(b >> 12) & 63] + chars[(b >> 6) & 63] + chars[b & 63];
    }
    const pad = buf.length % 3;
    if (pad === 1) result = result.slice(0, -2) + '==';
    if (pad === 2) result = result.slice(0, -1) + '=';
    return result;
  }

  function base64ToU8(str) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    str = str.replace(/=+$/, '');
    const buf = new Uint8Array(Math.floor(str.length * 3 / 4));
    let j = 0;
    for (let i = 0; i < str.length; i += 4) {
      const a = chars.indexOf(str[i]) << 18;
      const b = chars.indexOf(str[i+1]) << 12;
      const c = chars.indexOf(str[i+2]) << 6;
      const d = chars.indexOf(str[i+3]);
      buf[j++] = (a | b) >> 16;
      if (str[i+2] !== undefined) buf[j++] = (b | c) >> 8 & 255;
      if (str[i+3] !== undefined) buf[j++] = (c | d) & 255;
    }
    return buf;
  }

  // Initialize: check for existing wrapped key
  hasStoredKey();

  return {
    loadKeypair,
    generateKeypair,
    unlockWithPassword,
    hasStoredKey,
    hasWrappedKeySync,
    getPubkey,
    getSecretKey,
    getPubkeyHex,
    sign,
    deriveOrderKey,
    encryptForOrder,
    decryptForOrder,
    encryptListingData,
    decryptListingData,
    clearKeys,
    hashPubkey,
    u8ToHex,
    hexToU8,
    u8ToBase64,
    base64ToU8,
    getAllListingKeys,
    saveListingKey
  };
})();