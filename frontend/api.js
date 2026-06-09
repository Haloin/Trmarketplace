const API = (() => {
  const BASE = '';
  let authPubkeyHex = null;
  let authKeyHex = null;
  let workerPubkeyCache = null;

  function u64ToLeBytes(val) {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, BigInt(val), true);
    return new Uint8Array(buf);
  }

  async function makeAuthHeaders(path) {
    const hour = Math.floor(Date.now() / 3600000);
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    const nonceHex = CRYPTO.u8ToHex(nonceBytes);
    const authKeyBytes = CRYPTO.hexToU8(authKeyHex);
    const pubkeyBytes = CRYPTO.hexToU8(authPubkeyHex);
    const hourLE = u64ToLeBytes(hour);
    const pathBytes = new TextEncoder().encode(path);

    const hmacKey = await crypto.subtle.importKey(
      'raw', authKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const hmacInput = new Uint8Array([...pubkeyBytes, ...hourLE, ...pathBytes, ...nonceBytes]);
    const hmacSig = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, hmacInput));

    const challengeBytes = new Uint8Array([...hmacSig, ...pubkeyBytes, ...hourLE, ...nonceBytes]);
    const sigHex = CRYPTO.sign(CRYPTO.u8ToHex(challengeBytes));

    return {
      'x-auth-pubkey': authPubkeyHex,
      'x-auth-hmac': CRYPTO.u8ToHex(hmacSig),
      'x-auth-hour': String(hour),
      'x-auth-nonce': nonceHex,
      'x-auth-signature': sigHex,
    };
  }

  async function request(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (authPubkeyHex && authKeyHex && !path.startsWith('/auth/') && !path.startsWith('/public/')) {
      Object.assign(headers, await makeAuthHeaders(path.split('?')[0]));
    }
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) {
      const err = new Error(data.error || 'Request failed');
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async function getWorkerPubkey() {
    if (!workerPubkeyCache) {
      const res = await request('GET', '/public/worker-pubkey');
      workerPubkeyCache = res.worker_payment_pubkey_hex;
      if (!workerPubkeyCache) {
        throw new Error('Worker payment pubkey not configured on server');
      }
    }
    return workerPubkeyCache;
  }

  async function challenge(pubkeyHex) {
    return request('POST', '/auth/challenge', { pubkey: pubkeyHex });
  }

  async function verify(challengeId, pubkeyHex, signature) {
    return request('POST', '/auth/verify', { challenge_id: challengeId, pubkey: pubkeyHex, signature });
  }

  function setAuth(pubkeyHex, keyHex) {
    authPubkeyHex = pubkeyHex;
    authKeyHex = keyHex;
  }

  function logout() {
    authPubkeyHex = null;
    authKeyHex = null;
    workerPubkeyCache = null;
  }

  async function listListings(params = {}) {
    const qs = new URLSearchParams();
    if (params.q) qs.set('q', params.q);
    if (params.currency) qs.set('currency', params.currency);
    if (params.limit) qs.set('limit', params.limit);
    if (params.offset) qs.set('offset', params.offset);
    const query = qs.toString();
    return request('GET', '/listings' + (query ? '?' + query : ''));
  }

  async function getListing(id) {
    return request('GET', `/listings/${id}`);
  }

  async function createListing({ title, desc, price, currency }) {
    const payload = await CRYPTO.buildListingPayload(title, desc, price);
    const res = await request('POST', '/listings', {
      client_encrypted_blob: payload.blobHex,
      search_token: payload.searchTokenHex,
      currency: currency || 'XMR',
      status: 'active',
      nonce: CRYPTO.randomNonceHex(),
    });
    await CRYPTO.saveListingKey(res.id, payload.contentKeyHex);
    return { ...res, _decrypted: { title, desc, price } };
  }

  async function createOrder(listingId, currency, sellerPubkeyHex) {
    const workerPk = await getWorkerPubkey();
    const orderData = CRYPTO.buildInitialOrderData(listingId, currency, sellerPubkeyHex);
    const blobB64 = await CRYPTO.encryptWorkerOrder(orderData, workerPk);
    const res = await request('POST', '/orders', {
      client_encrypted_blob: blobB64,
      nonce: CRYPTO.randomNonceHex(),
      time_lock_days: 7,
    });
    await CRYPTO.saveOrderState(res.id, orderData, res.version);
    return { ...res, _orderData: orderData };
  }

  async function getOrder(id) {
    const res = await request('GET', `/orders/${id}`);
    const local = await CRYPTO.getOrderState(id);
    if (local) {
      if (res.version > local.version && local.data.state === 'pending') {
        local.data.state = 'funded';
        local.data.funded_at = Math.floor(Date.now() / 1000);
        await CRYPTO.saveOrderState(id, local.data, res.version);
      } else {
        local.version = res.version;
      }
      return { ...res, _orderData: local.data };
    }
    return res;
  }

  async function updateOrder(orderId, newState, extra = {}) {
    const local = await CRYPTO.getOrderState(orderId);
    if (!local) throw new Error('No local order state — cannot update');
    const orderData = { ...local.data, state: newState, ...extra };
    const now = Math.floor(Date.now() / 1000);
    if (newState === 'shipped') orderData.shipped_at = now;
    if (newState === 'confirmed') orderData.confirmed_at = now;
    if (newState === 'cancelled') orderData.state = 'cancelled';
    if (newState === 'disputed') {
      orderData.state = 'disputed';
      orderData.disputed_at = now;
    }

    const workerPk = await getWorkerPubkey();
    const blobB64 = await CRYPTO.encryptWorkerOrder(orderData, workerPk);
    const blobBytes = CRYPTO.base64ToU8(blobB64);
    const hour = Math.floor(Date.now() / 3600000);
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    const path = `/orders/${orderId}/update`;
    const sig = await CRYPTO.signTransition(orderId, local.version, blobBytes, nonceBytes, hour);

    const res = await request('POST', path, {
      client_encrypted_blob: blobB64,
      transition_signature: sig,
      nonce: CRYPTO.u8ToHex(nonceBytes),
      hour_bucket: hour,
    });
    await CRYPTO.saveOrderState(orderId, orderData, res.version);
    return { ...res, _orderData: orderData };
  }

  async function confirmOrder(id) { return updateOrder(id, 'confirmed'); }
  async function shipOrder(id) { return updateOrder(id, 'shipped'); }
  async function disputeOrder(id) { return updateOrder(id, 'disputed'); }
  async function cancelOrder(id) { return updateOrder(id, 'cancelled'); }
  async function refundOrder(id) { return updateOrder(id, 'refunded'); }

  async function getMessages(orderId) {
    const res = await request('GET', `/chat/${orderId}`);
    const keyHex = await CRYPTO.getChatKey(orderId);
    if (res.chat_encrypted_blob && keyHex) {
      try {
        const data = await CRYPTO.decryptChatBlob(res.chat_encrypted_blob, keyHex);
        return data.messages || [];
      } catch (_) {
        return [];
      }
    }
    return [];
  }

  async function sendMessage(orderId, text) {
    const existing = await getMessages(orderId);
    const myHex = CRYPTO.getPubkeyHex();
    existing.push({
      id: CRYPTO.randomNonceHex(),
      sender_pubkey_hash: CRYPTO.hashPubkey(myHex),
      body: text,
      created_at: Math.floor(Date.now() / 1000),
    });

    let keyHex = await CRYPTO.getChatKey(orderId);
    let blobB64;
    if (keyHex) {
      const w = await CRYPTO.initWasm();
      const plaintext = new TextEncoder().encode(JSON.stringify({ messages: existing }));
      const encrypted = w.encrypt_listing(plaintext, CRYPTO.hexToU8(keyHex));
      blobB64 = CRYPTO.u8ToBase64(encrypted);
    } else {
      const enc = await CRYPTO.encryptChatBlob(existing);
      blobB64 = enc.blobB64;
      keyHex = enc.keyHex;
      await CRYPTO.saveChatKey(orderId, keyHex);
    }

    return request('POST', `/chat/${orderId}`, {
      chat_encrypted_blob: blobB64,
      transition_signature: '0'.repeat(128),
      nonce: CRYPTO.randomNonceHex(),
    });
  }

  return {
    challenge, verify, setAuth, logout, getWorkerPubkey,
    listListings, getListing, createListing,
    createOrder, getOrder, updateOrder,
    confirmOrder, shipOrder, disputeOrder, cancelOrder, refundOrder,
    sendMessage, getMessages,
  };
})();
