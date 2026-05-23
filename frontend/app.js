// TorMarket SPA - Application Logic
const APP = (() => {
  let currentUser = null;
  let listingCache = {};

  function getEl(id) { return document.getElementById(id); }
  function show(id) { const el = getEl(id); if (el) el.style.display = ''; }
  function hide(id) { const el = getEl(id); if (el) el.style.display = 'none'; }
  function html(id, content) { const el = getEl(id); if (el) el.innerHTML = content; }
  function setStatus(id, msg, type) {
    const el = getEl(id);
    if (el) { el.textContent = msg; el.className = 'status-msg' + (type ? ' ' + type : ''); }
  }

  // Template rendering
  function renderTemplate(id) {
    const tpl = document.getElementById(id);
    if (!tpl) return null;
    const clone = tpl.content.cloneNode(true);
    return clone;
  }

  // Router
  function navigate(hash) {
    const route = hash.replace('#', '') || '/';
    const parts = route.split('/').filter(Boolean);
    const app = getEl('app');

    if (!CRYPTO.getPubkey()) {
      showPage(route, 'page-password');
      return;
    }

    if (route === '/' || route === '') {
      showPage(route, 'page-home');
      renderHome();
    } else if (route === '/login' || route === '/unlock') {
      showPage(route, 'page-password');
      initPasswordPage();
    } else if (route === '/create') {
      showPage(route, 'page-create');
    } else if (route === '/orders') {
      showPage(route, 'page-orders');
      renderOrders();
    } else if (parts[0] === 'listing') {
      showPage(route, 'page-listing');
      renderListing(parts[1]);
    } else if (parts[0] === 'order') {
      showPage(route, 'page-order');
      renderOrder(parts[1]);
    }
  }

  function showPage(route, templateId) {
    const app = getEl('app');
    app.innerHTML = '';
    const content = renderTemplate(templateId);
    if (content) app.appendChild(content);
    window.scrollTo(0, 0);
  }

  // Password/Auth flow
  async function handlePasswordSubmit(e) {
    e.preventDefault();
    const password = getEl('password-input')?.value;
    const confirm = getEl('confirm-password-input')?.value;
    const status = getEl('password-status');
    const isNewUser = getEl('is-new-user')?.value === 'true';

    if (!password || password.length < 12) {
      status.textContent = 'Password must be at least 12 characters';
      status.className = 'status-msg error';
      return;
    }

    if (isNewUser && password !== confirm) {
      status.textContent = 'Passwords do not match';
      status.className = 'status-msg error';
      return;
    }

    status.textContent = isNewUser ? 'Creating your identity...' : 'Unlocking...';
    status.className = 'status-msg';
    const btn = getEl('btn-unlock');
    if (btn) btn.disabled = true;

    try {
      let kp;
      if (isNewUser) {
        kp = await CRYPTO.generateKeypair(password);
      } else {
        kp = await CRYPTO.unlockWithPassword(password);
      }

      if (!kp) {
        throw new Error('Failed to initialize keypair');
      }

      status.textContent = 'Connecting...';
      const pubkeyHex = CRYPTO.getPubkeyHex();

      const challenge = await API.challenge(pubkeyHex);
      const signature = CRYPTO.sign(challenge.challenge);
      const result = await API.verify(challenge.challenge_id, pubkeyHex, signature);

      if (result.token) {
        status.textContent = 'Connected!';
        status.className = 'status-msg success';
        show('key-display');
        const pubkeyDisplay = getEl('pubkey-display');
        if (pubkeyDisplay) pubkeyDisplay.textContent = pubkeyHex;
        hide('btn-unlock');
        setTimeout(() => navigate('#/'), 800);
      }
    } catch(e) {
      status.textContent = e.message || 'Authentication failed';
      status.className = 'status-msg error';
      const btn = getEl('btn-unlock');
      if (btn) btn.disabled = false;
    }
  }

  // Initialize password page based on whether user has existing key
  async function initPasswordPage() {
    const hasExistingKey = await CRYPTO.hasStoredKey();
    const isNewUserInput = getEl('is-new-user');
    const confirmGroup = getEl('confirm-group');
    const btn = getEl('btn-unlock');
    
    if (hasExistingKey) {
      // Existing user - unlock mode
      if (isNewUserInput) isNewUserInput.value = 'false';
      if (confirmGroup) hide('confirm-group');
      const confirmInput = getEl('confirm-password-input');
      if (confirmInput) confirmInput.required = false;
      if (btn) btn.textContent = 'Unlock';
    } else {
      // New user - create mode
      if (isNewUserInput) isNewUserInput.value = 'true';
      if (confirmGroup) show('confirm-group');
      const confirmInput = getEl('confirm-password-input');
      if (confirmInput) confirmInput.required = true;
      if (btn) btn.textContent = 'Create Identity';
    }
  }

  async function login() {
    navigate('#/unlock');
  }

  async function logout() {
    await CRYPTO.clearKeys();
    try {
      await API.logout();
    } catch(e) {
      console.warn('Logout API call failed:', e.message);
    }
    navigate('#/login');
  }

  // Home - Listing grid
  async function renderHome() {
    const grid = getEl('listing-grid');
    if (!grid) return;
    setStatus('listings-status', 'Loading...');
    try {
      const result = await API.listListings({ limit: 50 });
      grid.innerHTML = '';
      if (result.listings && result.listings.length > 0) {
        result.listings.forEach(l => {
          const card = document.createElement('div');
          card.className = 'listing-card';
          card.onclick = () => navigate('#/listing/' + l.id);
          // Decrypt title (if we have the key - for public listings we show truncated hex)
          const title = l.encrypted_data ? l.encrypted_data.slice(0, 16) + '...' : 'Untitled';
          card.innerHTML = `
            <h3>${escapeHtml(title)}</h3>
            <div class="meta">${escapeHtml(l.currency)}</div>
            <div class="price">${escapeHtml(l.price_amount)} ${escapeHtml(l.currency)}</div>
          `;
          grid.appendChild(card);
        });
        setStatus('listings-status', '');
      } else {
        setStatus('listings-status', 'No listings found');
      }
    } catch(e) {
      setStatus('listings-status', 'Error: ' + e.message, 'error');
    }
  }

  // Search
  async function search() {
    const q = getEl('search-input')?.value?.toLowerCase() || '';
    const currency = getEl('currency-filter')?.value || '';
    const grid = getEl('listing-grid');
    if (!grid) return;

    try {
      const result = await API.listListings({ currency: currency || undefined, limit: 50 });
      grid.innerHTML = '';
      if (result.listings && result.listings.length > 0) {
        const filtered = q ? result.listings.filter(l =>
          l.price_amount?.includes(q) ||
          l.currency?.toLowerCase().includes(q) ||
          (l.encrypted_data && l.encrypted_data.toLowerCase().includes(q))
        ) : result.listings;

        filtered.forEach(l => {
          const card = document.createElement('div');
          card.className = 'listing-card';
          card.onclick = () => navigate('#/listing/' + l.id);
          const title = l.encrypted_data ? l.encrypted_data.slice(0, 16) + '...' : 'Untitled';
          card.innerHTML = `
            <h3>${escapeHtml(title)}</h3>
            <div class="meta">${escapeHtml(l.currency)}</div>
            <div class="price">${escapeHtml(l.price_amount)} ${escapeHtml(l.currency)}</div>
          `;
          grid.appendChild(card);
        });
      }
      setStatus('listings-status', grid.children.length === 0 ? 'No results' : '');
    } catch(e) {
      setStatus('listings-status', 'Search error', 'error');
    }
  }

  // Listing detail
  async function renderListing(id) {
    const detail = getEl('listing-detail');
    if (!detail) return;
    detail.innerHTML = '<p class="status-msg">Loading...</p>';
    try {
      const listing = await API.getListing(id);
      detail.innerHTML = `
        <div class="listing-detail-card">
          <h2>${escapeHtml(listing.encrypted_data ? listing.encrypted_data.slice(0, 32) + '...' : 'Untitled')}</h2>
          <div class="meta">Seller: <code>${escapeHtml(listing.seller_pubkey_hash ? listing.seller_pubkey_hash.slice(0, 16) + '...' : 'unknown')}</code></div>
          <div class="price">${escapeHtml(listing.price_amount)} ${escapeHtml(listing.currency)}</div>
          <div class="meta">Listed: ${new Date(listing.created_at * 1000).toLocaleDateString()}</div>
          <div class="actions">
            <button class="btn-primary" onclick="APP.buy('${id}', '${listing.currency}')">Buy with ${listing.currency}</button>
          </div>
        </div>
      `;
    } catch(e) {
      detail.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  // Buy - Create order
  async function buy(listingId, currency) {
    try {
      const order = await API.createOrder(listingId, currency);
      navigate('#/order/' + order.id);
    } catch(e) {
      alert('Error: ' + e.message);
    }
  }

  // Create listing
  async function createListing(event) {
    event.preventDefault();
    const title = getEl('listing-title')?.value;
    const desc = getEl('listing-desc')?.value;
    const price = getEl('listing-price')?.value;
    const currency = getEl('listing-currency')?.value;
    setStatus('create-status', 'Encrypting...');

    // Encrypt listing data client-side
    const encKey = nacl.randomBytes(32);
    const plaintext = JSON.stringify({ title, desc, price });
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(new TextEncoder().encode(plaintext), nonce, encKey);
    if (!encrypted) {
      setStatus('create-status', 'Encryption failed', 'error');
      return false;
    }
    const encryptedHex = CRYPTO.u8ToHex(new Uint8Array([...nonce, ...encrypted]));

    // Store encryption key in IndexedDB for future reference
    const listingId = CRYPTO.u8ToHex(nacl.randomBytes(32));
    await CRYPTO.saveListingKey(listingId, CRYPTO.u8ToHex(encKey));

    try {
      setStatus('create-status', 'Submitting...');
      const result = await API.createListing({
        encrypted_data: encryptedHex,
        currency: currency,
        price_amount: price
      });
      setStatus('create-status', 'Listing created!', 'success');
      getEl('create-form')?.reset();
      setTimeout(() => navigate('#/'), 1500);
    } catch(e) {
      setStatus('create-status', 'Error: ' + e.message, 'error');
    }
    return false;
  }

  // Orders list
  async function renderOrders() {
    const list = getEl('orders-list');
    if (!list) return;
    list.innerHTML = '<p class="status-msg">Loading...</p>';
    try {
      // Since we don't have a "my orders" endpoint, we'll show a static message
      // In production, this would use a user-specific query
      list.innerHTML = `
        <p class="status-msg">Orders appear here when you buy or sell.</p>
        <p>Your pubkey hash: <code>${escapeHtml(CRYPTO.hashPubkey(CRYPTO.getPubkeyHex()).slice(0, 16))}...</code></p>
      `;
    } catch(e) {
      list.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  // Order detail + Chat
  async function renderOrder(orderId) {
    const detail = getEl('order-detail');
    const chat = getEl('order-chat');
    if (!detail) return;
    detail.innerHTML = '<p class="status-msg">Loading...</p>';

    try {
      const order = await API.getOrder(orderId);
      const stateClass = 'state-' + order.state;
      detail.innerHTML = `
        <div class="order-card">
          <div class="state ${stateClass}">${escapeHtml(order.state)}</div>
          <p>Order: <code>${escapeHtml(orderId.slice(0, 16))}...</code></p>
          <p>Currency: ${escapeHtml(order.currency)}</p>
          <p>Amount: ${escapeHtml(order.escrow_amount || 'pending')}</p>
          <p>Escrow: <code>${escapeHtml(order.escrow_address || 'generating...')}</code></p>
          <p>Time lock: ${order.time_lock_seconds / 86400} days</p>
          <div class="actions" id="order-actions">
            ${order.state === 'shipped' ? `<button class="btn-primary" onclick="APP.confirm('${orderId}')">Confirm Receipt</button><button class="btn-danger" onclick="APP.dispute('${orderId}')">Dispute</button>` : ''}
            ${order.state === 'disputed' ? `<button class="btn-danger" onclick="APP.refund('${orderId}')">Request Refund</button>` : ''}
            ${order.state === 'pending' ? `<button class="btn-danger" onclick="APP.cancel('${orderId}')">Cancel Order</button>` : ''}
            ${order.state === 'funded' ? `<span class="status-msg success">Payment received!</span><button class="btn-primary" onclick="APP.ship('${orderId}')">Ship Order</button>` : ''}
          </div>
        </div>
      `;

// Load chat
        if (chat) {
          try {
            const msgs = await API.getMessages(orderId);
            chat.innerHTML = '';
            if (msgs && msgs.length > 0) {
              const myPubkeyHash = CRYPTO.hashPubkey(CRYPTO.getPubkeyHex());
              const mySecretKey = CRYPTO.getSecretKey();

              msgs.forEach(m => {
                const isMine = m.sender_pubkey_hash === CRYPTO.u8ToHex(myPubkeyHash);
                const msgDiv = document.createElement('div');
                msgDiv.className = 'chat-msg ' + (isMine ? 'mine' : 'theirs');
                
                // Decrypt message using nacl.box
                let msgText = ' [encrypted] ';
                try {
                  const data = CRYPTO.hexToU8(m.encrypted_body);
                  const nonce = data.slice(0, 24);
                  const senderPubkey = data.slice(24, 56);
                  const encrypted = data.slice(56);
                  
                  if (mySecretKey) {
                    const decrypted = nacl.box.open(encrypted, nonce, senderPubkey, mySecretKey);
                    if (decrypted) {
                      msgText = new TextDecoder().decode(decrypted);
                    }
                  }
                } catch(e) {
                  console.warn('Message decryption failed:', e.message);
                }
                
                msgDiv.innerHTML = `
                  <div>${escapeHtml(msgText)}</div>
                  <div class="time">${new Date(m.created_at * 1000).toLocaleTimeString()}</div>
                `;
                chat.appendChild(msgDiv);
              });
              chat.scrollTop = chat.scrollHeight;
          } else {
            chat.innerHTML = '<p style="color:var(--text-dim);font-size:0.9em;">No messages yet</p>';
          }
        } catch(e) {
          chat.innerHTML = '<p class="status-msg error">Could not load messages</p>';
        }
      }
    } catch(e) {
      detail.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  // Order actions
  async function confirm(orderId) {
    try {
      await API.confirmOrder(orderId);
      renderOrder(orderId);
    } catch(e) { alert('Error: ' + e.message); }
  }

  async function ship(orderId) {
    try {
      await API.shipOrder(orderId);
      renderOrder(orderId);
    } catch(e) { alert('Error: ' + e.message); }
  }

  async function dispute(orderId) {
    try {
      await API.disputeOrder(orderId);
      renderOrder(orderId);
    } catch(e) { alert('Error: ' + e.message); }
  }

  async function cancel(orderId) {
    if (!confirm('Cancel this order?')) return;
    try {
      await API.cancelOrder(orderId);
      renderOrder(orderId);
    } catch(e) { alert('Error: ' + e.message); }
  }

  async function refund(orderId) {
    if (!confirm('Request refund? This will reclaim your funds if time-lock has expired.')) return;
    try {
      await API.refundOrder(orderId);
      renderOrder(orderId);
    } catch(e) { alert('Error: ' + e.message); }
  }

  // Chat
  async function sendMessage() {
    const input = getEl('chat-input');
    const orderId = window.location.hash.replace('#/order/', '');
    if (!input || !input.value.trim() || !orderId) return;

    const msg = input.value.trim();
    input.value = '';

    const myPubkeyHex = CRYPTO.getPubkeyHex();
    const mySecretKey = CRYPTO.getSecretKey();
    if (!myPubkeyHex || !mySecretKey) {
      alert('Not authenticated');
      return;
    }

    try {
      const order = await API.getOrder(orderId);
      
      const isBuyer = order.buyer_pubkey_hash === CRYPTO.u8ToHex(CRYPTO.hashPubkey(myPubkeyHex));
      const recipientPubkeyHex = isBuyer ? order.seller_pubkey : order.buyer_pubkey;
      
      if (!recipientPubkeyHex) {
        alert('Cannot encrypt: missing recipient pubkey');
        return;
      }

      const recipientPubkey = CRYPTO.hexToU8(recipientPubkeyHex);
      const nonce = nacl.randomBytes(24);
      const msgBytes = new TextEncoder().encode(msg);
      
      const encrypted = nacl.box(msgBytes, nonce, recipientPubkey, mySecretKey);
      
      if (!encrypted) {
        alert('Encryption failed');
        return;
      }

      const encryptedHex = CRYPTO.u8ToHex(new Uint8Array([...nonce, ...encrypted]));

      await API.sendMessage(orderId, encryptedHex);
      renderOrder(orderId);
    } catch(e) {
      alert('Send failed: ' + e.message);
    }
  }

  // Utility
  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  // Initialize
  async function init() {
    window.addEventListener('hashchange', () => navigate(window.location.hash));

    // Check for existing keypair (user identity)
    const pubkey = CRYPTO.getPubkeyHex();
    currentUser = pubkey;

    // Initial route - if no keypair, force password page
    if (!pubkey) {
      navigate(window.location.hash || '#/unlock');
    } else {
      navigate(window.location.hash || '#/');
    }
  }

  // Auto-refresh for orders (poll every 30s)
  setInterval(() => {
    const hash = window.location.hash;
    if (hash.startsWith('#/order/')) {
      renderOrder(hash.replace('#/order/', ''));
    }
  }, 30000);

  document.addEventListener('DOMContentLoaded', init);
  if (document.readyState !== 'loading') init();

  return {
    login, logout, navigate,
    renderHome, renderListing, renderOrders, renderOrder,
    createListing, search, buy,
    confirm, dispute, cancel, refund,
    sendMessage
  };
})();
