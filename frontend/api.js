// REST API client for TorMarket backend
const API = (() => {
  const BASE = '';

  async function request(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    try {
      const res = await fetch(BASE + path, {
        method,
        headers,
        credentials: 'include',
        body: body ? JSON.stringify(body) : undefined
      });
      const data = await res.json();
      if (!res.ok) {
        const err = new Error(data.error || 'Request failed');
        err.status = res.status;
        err.data = data;
        throw err;
      }
      return data;
    } catch(e) {
      if (e.status) throw e;
      throw new Error('Network error: ' + e.message);
    }
  }

  async function challenge(pubkeyHex) {
    return await request('GET', `/auth/challenge/${pubkeyHex}`);
  }

  async function verify(challengeId, pubkeyHex, signature) {
    return await request('POST', '/auth/verify', {
      challenge_id: challengeId,
      pubkey: pubkeyHex,
      signature: signature,
      algorithm: 'ed25519'
    });
  }

  async function logout() {
    return await request('POST', '/auth/logout');
  }

  // Listings
  async function listListings(params) {
    const qs = new URLSearchParams();
    if (params.q) qs.set('q', params.q);
    if (params.currency) qs.set('currency', params.currency);
    if (params.limit) qs.set('limit', params.limit);
    if (params.offset) qs.set('offset', params.offset);
    return await request('GET', '/listings?' + qs.toString());
  }

  async function getListing(id) {
    return await request('GET', `/listings/${id}`);
  }

  async function createListing(listingData) {
    return await request('POST', '/listings', {
      encrypted_data: listingData.encrypted_data,
      encrypted_search: listingData.encrypted_search || null,
      currency: listingData.currency,
      price_amount: listingData.price_amount,
      seller_pubkey: CRYPTO.getPubkeyHex()
    });
  }

  async function deleteListing(id) {
    return await request('DELETE', `/listings/${id}`);
  }

  // Orders
  async function createOrder(listingId, currency) {
    return await request('POST', '/orders', {
      listing_id: listingId,
      currency: currency || undefined,
      buyer_pubkey: CRYPTO.getPubkeyHex()
    });
  }

  async function getOrder(id) {
    return await request('GET', `/orders/${id}`);
  }

  async function confirmOrder(id) {
    return await request('POST', `/orders/${id}/confirm`);
  }

  async function shipOrder(id) {
    return await request('POST', `/orders/${id}/ship`);
  }

  async function disputeOrder(id) {
    return await request('POST', `/orders/${id}/dispute`);
  }

  async function cancelOrder(id) {
    return await request('POST', `/orders/${id}/cancel`);
  }

  async function refundOrder(id) {
    return await request('POST', `/orders/${id}/refund`);
  }

  // Chat
  async function sendMessage(orderId, encryptedBody) {
    return await request('POST', `/chat/${orderId}`, {
      encrypted_body: encryptedBody
    });
  }

  async function getMessages(orderId) {
    return await request('GET', `/chat/${orderId}`);
  }

  return {
    challenge, verify, logout,
    listListings, getListing, createListing, deleteListing,
    createOrder, getOrder, confirmOrder, shipOrder, disputeOrder, cancelOrder, refundOrder,
    sendMessage, getMessages
  };
})();