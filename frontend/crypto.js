// Client-side crypto: WASM (ChaCha20/X25519) + tweetnacl (Ed25519 auth)
const CRYPTO = (() => {
  let wasm = null;
  let wasmInit = null;
  let keypair = null;
  let hasWrappedKey = false;

  const DB_NAME = 'tor_marketplace_keys';
  const STORE_NAME = 'keyvault';
  const LISTING_KEYS_STORE = 'listing_keys';
  const ORDER_STATE_STORE = 'order_state';
  const SEARCH_KEY_ID = 'search_key';
  const DB_VERSION = 3;

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
        if (!db.objectStoreNames.contains(ORDER_STATE_STORE)) {
          db.createObjectStore(ORDER_STATE_STORE, { keyPath: 'id' });
        }
      };
    });
  }

  async function dbGet(store, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, 'readonly');
      const req = tx.objectStore(store).get(key);
      req.onsuccess = () => resolve(req.result?.value);
      req.onerror = () => reject(req.error);
    });
  }

  async function dbPut(store, key, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, 'readwrite');
      const req = tx.objectStore(store).put({ id: key, value });
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async function dbDelete(store, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, 'readwrite');
      const req = tx.objectStore(store).delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async function initWasm() {
    if (!wasmInit) {
      wasmInit = (async () => {
        const mod = await import('/wasm/tor_marketplace_wasm.js');
        await mod.default();
        wasm = mod;
      })();
    }
    await wasmInit;
    return wasm;
  }

  function u8ToHex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToU8(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function u8ToBase64(buf) {
    let binary = '';
    buf.forEach(b => { binary += String.fromCharCode(b); });
    return btoa(binary);
  }

  function base64ToU8(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomNonceHex() {
    return u8ToHex(crypto.getRandomValues(new Uint8Array(16)));
  }

  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      keyMaterial, 256
    );
    return new Uint8Array(bits);
  }

  async function wrapKey(secretKey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const nonce = nacl.randomBytes(24);
    const wrapped = nacl.secretbox(secretKey, nonce, key);
    return { salt: u8ToBase64(salt), nonce: u8ToBase64(nonce), wrapped: u8ToBase64(wrapped) };
  }

  async function unwrapKey(wrappedData, password) {
    const salt = base64ToU8(wrappedData.salt);
    const nonce = base64ToU8(wrappedData.nonce);
    const wrapped = base64ToU8(wrappedData.wrapped);
    const key = await deriveKey(password, salt);
    const secretKey = nacl.secretbox.open(wrapped, nonce, key);
    if (!secretKey) throw new Error('Wrong password');
    return secretKey;
  }

  async function hasStoredKey() {
    const wrapped = await dbGet(STORE_NAME, 'wrapped_key');
    return !!wrapped;
  }

  async function unlockWithPassword(password) {
    const wrapped = await dbGet(STORE_NAME, 'wrapped_key');
    if (!wrapped) throw new Error('No stored identity');
    const seckey = await unwrapKey(wrapped, password);
    const pubkey = base64ToU8(await dbGet(STORE_NAME, 'pubkey'));
    keypair = { pubkey, seckey };
    hasWrappedKey = true;
    return keypair;
  }

  async function createKeypairWithPassword(password) {
    if (!password || password.length < 12) {
      throw new Error('Password must be at least 12 characters');
    }
    const kp = nacl.sign.keyPair();
    keypair = { pubkey: kp.publicKey, seckey: kp.secretKey };
    const wrapped = await wrapKey(kp.secretKey, password);
    await dbPut(STORE_NAME, 'wrapped_key', wrapped);
    await dbPut(STORE_NAME, 'pubkey', u8ToBase64(kp.publicKey));
    await dbPut(STORE_NAME, 'created_at', Date.now());
    const searchKey = crypto.getRandomValues(new Uint8Array(32));
    await dbPut(STORE_NAME, SEARCH_KEY_ID, u8ToHex(searchKey));
    hasWrappedKey = true;
    return keypair;
  }

  async function generateKeypair(password) {
    return createKeypairWithPassword(password);
  }

  function getPubkey() { return keypair ? keypair.pubkey : null; }
  function getSecretKey() { return keypair ? keypair.seckey : null; }
  function getPubkeyHex() { return keypair ? u8ToHex(keypair.pubkey) : null; }

  function sign(msgHex) {
    if (!keypair) return null;
    const sig = nacl.sign.detached(hexToU8(msgHex), keypair.seckey);
    return u8ToHex(sig);
  }

  function hashPubkey(pubkeyHex) {
    const h = nacl.hash(hexToU8(pubkeyHex));
    return u8ToHex(h.slice(0, 32));
  }

  async function getSearchKeyHex() {
    let key = await dbGet(STORE_NAME, SEARCH_KEY_ID);
    if (!key) {
      key = u8ToHex(crypto.getRandomValues(new Uint8Array(32)));
      await dbPut(STORE_NAME, SEARCH_KEY_ID, key);
    }
    return key;
  }

  async function buildListingPayload(title, desc, price) {
    const w = await initWasm();
    const contentKey = w.generate_content_key();
    const plaintext = new TextEncoder().encode(JSON.stringify({ title, desc, price }));
    const encrypted = w.encrypt_listing(plaintext, contentKey);
    const searchKey = hexToU8(await getSearchKeyHex());
    const token = w.search_token(title.toLowerCase().trim(), searchKey);
    return {
      blobHex: u8ToHex(encrypted),
      contentKeyHex: u8ToHex(contentKey),
      searchTokenHex: u8ToHex(token),
    };
  }

  async function decryptListingBlob(blobHex, contentKeyHex) {
    const w = await initWasm();
    const decrypted = w.decrypt_listing(hexToU8(blobHex), hexToU8(contentKeyHex));
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  async function saveListingKey(listingId, contentKeyHex) {
    await dbPut(LISTING_KEYS_STORE, listingId, contentKeyHex);
  }

  async function getListingKey(listingId) {
    return dbGet(LISTING_KEYS_STORE, listingId);
  }

  async function encryptWorkerOrder(orderData, workerPubkeyHex) {
    const w = await initWasm();
    const plaintext = new TextEncoder().encode(JSON.stringify(orderData));
    const blob = w.encrypt_order(plaintext, hexToU8(workerPubkeyHex));
    return u8ToBase64(blob);
  }

  function buildInitialOrderData(listingId, currency, sellerPubkeyHex) {
    const buyerHex = getPubkeyHex();
    const now = Math.floor(Date.now() / 1000);
    return {
      listing_id: listingId,
      buyer_pubkey_hash: hashPubkey(buyerHex),
      seller_pubkey_hash: sellerPubkeyHex ? hashPubkey(sellerPubkeyHex) : '',
      buyer_pubkey: buyerHex,
      seller_pubkey: sellerPubkeyHex || null,
      state: 'pending',
      currency: currency || 'XMR',
      escrow_address: null,
      escrow_amount: null,
      time_lock_seconds: 7 * 86400,
      created_at: now,
      funded_at: null,
      shipped_at: null,
      confirmed_at: null,
      released_at: null,
      refunded_at: null,
      expires_at: null,
      disputed_at: null,
      dispute_id: null,
      owner_pubkey: null,
      fee_percent: null,
      fee_address: null,
      dispute: null,
      chat_messages: [],
      settlement_txid: null,
    };
  }

  async function saveOrderState(orderId, data, version) {
    await dbPut(ORDER_STATE_STORE, orderId, { data, version });
    const ids = (await dbGet(STORE_NAME, 'order_ids')) || [];
    if (!ids.includes(orderId)) {
      ids.push(orderId);
      await dbPut(STORE_NAME, 'order_ids', ids);
    }
  }

  async function getOrderState(orderId) {
    return dbGet(ORDER_STATE_STORE, orderId);
  }

  async function listLocalOrderIds() {
    return (await dbGet(STORE_NAME, 'order_ids')) || [];
  }

  async function signTransition(orderIdHex, prevVersion, blobBytes, nonceBytes, hourBucket) {
    const w = await initWasm();
    const seed = keypair.seckey.slice(0, 32);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', blobBytes));
    const sig = w.sign_transition(
      seed,
      hexToU8(orderIdHex),
      prevVersion,
      hash,
      nonceBytes,
      hourBucket
    );
    return u8ToHex(sig);
  }

  async function encryptChatBlob(messages) {
    const w = await initWasm();
    const key = w.generate_content_key();
    const plaintext = new TextEncoder().encode(JSON.stringify({ messages }));
    const encrypted = w.encrypt_listing(plaintext, key);
    return { blobB64: u8ToBase64(encrypted), keyHex: u8ToHex(key) };
  }

  async function decryptChatBlob(blobB64, keyHex) {
    const w = await initWasm();
    const decrypted = w.decrypt_listing(base64ToU8(blobB64), hexToU8(keyHex));
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  async function saveChatKey(orderId, keyHex) {
    await dbPut(ORDER_STATE_STORE, `chat:${orderId}`, keyHex);
  }

  async function getChatKey(orderId) {
    return dbGet(ORDER_STATE_STORE, `chat:${orderId}`);
  }

  async function clearKeys() {
    keypair = null;
    hasWrappedKey = false;
    for (const store of [STORE_NAME, LISTING_KEYS_STORE, ORDER_STATE_STORE]) {
      const db = await openDB();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const req = tx.objectStore(store).clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    }
    localStorage.removeItem('tm_keypair');
  }

  // Restore pubkey on page load (requires password to sign)
  async function tryRestorePubkey() {
    const pubkeyB64 = await dbGet(STORE_NAME, 'pubkey');
    if (pubkeyB64) {
      // pubkey only — user must unlock for signing
      return u8ToHex(base64ToU8(pubkeyB64));
    }
    return null;
  }

  return {
    initWasm,
    u8ToHex, hexToU8, u8ToBase64, base64ToU8,
    randomNonceHex,
    hasStoredKey, unlockWithPassword, createKeypairWithPassword, generateKeypair,
    getPubkey, getSecretKey, getPubkeyHex, sign, hashPubkey,
    buildListingPayload, decryptListingBlob, saveListingKey, getListingKey,
    encryptWorkerOrder, buildInitialOrderData,
    saveOrderState, getOrderState, listLocalOrderIds,
    signTransition,
    encryptChatBlob, decryptChatBlob, saveChatKey, getChatKey,
    getSearchKeyHex,
    clearKeys, tryRestorePubkey,
  };
})();
