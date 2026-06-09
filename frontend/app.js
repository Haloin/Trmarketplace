// TorMarket SPA - Application Logic
const APP = (() => {
  function getEl(id) { return document.getElementById(id); }
  function show(id) { const el = getEl(id); if (el) el.style.display = ''; }
  function hide(id) { const el = getEl(id); if (el) el.style.display = 'none'; }
  function setStatus(id, msg, type) {
    const el = getEl(id);
    if (el) { el.textContent = msg; el.className = 'status-msg' + (type ? ' ' + type : ''); }
  }

  function renderTemplate(id) {
    const tpl = document.getElementById(id);
    if (!tpl) return null;
    return tpl.content.cloneNode(true);
  }

  function navigate(hash) {
    const route = hash.replace('#', '') || '/';
    const parts = route.split('/').filter(Boolean);

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
      await CRYPTO.initWasm();
      if (isNewUser) {
        await CRYPTO.generateKeypair(password);
      } else {
        await CRYPTO.unlockWithPassword(password);
      }

      status.textContent = 'Connecting...';
      const pubkeyHex = CRYPTO.getPubkeyHex();
      const challenge = await API.challenge(pubkeyHex);
      const signature = CRYPTO.sign(challenge.challenge);
      const result = await API.verify(challenge.challenge_id, pubkeyHex, signature);

      if (result.auth_key) {
        API.setAuth(pubkeyHex, result.auth_key);
        status.textContent = 'Connected!';
        status.className = 'status-msg success';
        show('key-display');
        const pubkeyDisplay = getEl('pubkey-display');
        if (pubkeyDisplay) pubkeyDisplay.textContent = pubkeyHex;
        hide('btn-unlock');
        setTimeout(() => navigate('#/'), 800);
      }
    } catch (err) {
      status.textContent = err.message || 'Authentication failed';
      status.className = 'status-msg error';
      if (btn) btn.disabled = false;
    }
  }

  async function initPasswordPage() {
    const hasExistingKey = await CRYPTO.hasStoredKey();
    const isNewUserInput = getEl('is-new-user');
    const confirmGroup = getEl('confirm-group');
    const btn = getEl('btn-unlock');

    if (hasExistingKey) {
      if (isNewUserInput) isNewUserInput.value = 'false';
      if (confirmGroup) hide('confirm-group');
      const confirmInput = getEl('confirm-password-input');
      if (confirmInput) confirmInput.required = false;
      if (btn) btn.textContent = 'Unlock';
    } else {
      if (isNewUserInput) isNewUserInput.value = 'true';
      if (confirmGroup) show('confirm-group');
      const confirmInput = getEl('confirm-password-input');
      if (confirmInput) confirmInput.required = true;
      if (btn) btn.textContent = 'Create Identity';
    }
  }

  async function logout() {
    await CRYPTO.clearKeys();
    API.logout();
    navigate('#/unlock');
  }

  async function listingTitle(listing) {
    const key = await CRYPTO.getListingKey(listing.id);
    if (key && listing.client_encrypted_blob) {
      try {
        const data = await CRYPTO.decryptListingBlob(listing.client_encrypted_blob, key);
        return data.title || 'Untitled';
      } catch (_) { /* fall through */ }
    }
    return 'Encrypted listing';
  }

  async function renderHome() {
    const grid = getEl('listing-grid');
    if (!grid) return;
    setStatus('listings-status', 'Loading...');
    try {
      const result = await API.listListings({ limit: 50 });
      grid.innerHTML = '';
      if (result.listings?.length > 0) {
        for (const l of result.listings) {
          const title = await listingTitle(l);
          const card = document.createElement('div');
          card.className = 'listing-card';
          card.onclick = () => navigate('#/listing/' + l.id);
          card.innerHTML = `
            <h3>${escapeHtml(title)}</h3>
            <div class="meta">${escapeHtml(l.currency)} · ${escapeHtml(l.status)}</div>
          `;
          grid.appendChild(card);
        }
        setStatus('listings-status', '');
      } else {
        setStatus('listings-status', 'No listings found');
      }
    } catch (e) {
      setStatus('listings-status', 'Error: ' + e.message, 'error');
    }
  }

  async function search() {
    const q = getEl('search-input')?.value?.trim().toLowerCase() || '';
    const currency = getEl('currency-filter')?.value || '';
    const grid = getEl('listing-grid');
    if (!grid) return;

    try {
      let result;
      if (q) {
        const searchKey = await CRYPTO.getSearchKeyHex();
        const w = await CRYPTO.initWasm();
        const tokenHex = CRYPTO.u8ToHex(w.search_token(q, CRYPTO.hexToU8(searchKey)));
        result = await API.listListings({ q: tokenHex, currency: currency || undefined, limit: 50 });
      } else {
        result = await API.listListings({ currency: currency || undefined, limit: 50 });
      }
      grid.innerHTML = '';
      for (const l of result.listings || []) {
        const title = await listingTitle(l);
        const card = document.createElement('div');
        card.className = 'listing-card';
        card.onclick = () => navigate('#/listing/' + l.id);
        card.innerHTML = `
          <h3>${escapeHtml(title)}</h3>
          <div class="meta">${escapeHtml(l.currency)}</div>
        `;
        grid.appendChild(card);
      }
      setStatus('listings-status', grid.children.length === 0 ? 'No results' : '');
    } catch (e) {
      setStatus('listings-status', 'Search error: ' + e.message, 'error');
    }
  }

  async function renderListing(id) {
    const detail = getEl('listing-detail');
    if (!detail) return;
    detail.innerHTML = '<p class="status-msg">Loading...</p>';
    try {
      const listing = await API.getListing(id);
      let title = 'Encrypted listing';
      let desc = '';
      let price = '';
      const key = await CRYPTO.getListingKey(id);
      if (key) {
        const data = await CRYPTO.decryptListingBlob(listing.client_encrypted_blob, key);
        title = data.title || title;
        desc = data.desc || '';
        price = data.price || '';
      }
      detail.innerHTML = `
        <div class="listing-detail-card">
          <h2>${escapeHtml(title)}</h2>
          <p>${escapeHtml(desc)}</p>
          <div class="price">${escapeHtml(price)} ${escapeHtml(listing.currency)}</div>
          <div class="meta">Status: ${escapeHtml(listing.status)}</div>
          <div class="actions">
            <button class="btn-primary" onclick="APP.buy('${id}', '${listing.currency}')">Buy with ${escapeHtml(listing.currency)}</button>
          </div>
        </div>
      `;
    } catch (e) {
      detail.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  async function buy(listingId, currency) {
    try {
      const order = await API.createOrder(listingId, currency, null);
      navigate('#/order/' + order.id);
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  async function createListing(event) {
    event.preventDefault();
    const title = getEl('listing-title')?.value;
    const desc = getEl('listing-desc')?.value;
    const price = getEl('listing-price')?.value;
    const currency = getEl('listing-currency')?.value;
    setStatus('create-status', 'Encrypting...');
    try {
      await API.createListing({ title, desc, price, currency });
      setStatus('create-status', 'Listing created!', 'success');
      getEl('create-form')?.reset();
      setTimeout(() => navigate('#/'), 1500);
    } catch (e) {
      setStatus('create-status', 'Error: ' + e.message, 'error');
    }
    return false;
  }

  async function renderOrders() {
    const list = getEl('orders-list');
    if (!list) return;
    list.innerHTML = '<p class="status-msg">Loading...</p>';
    try {
      const ids = await CRYPTO.listLocalOrderIds();
      if (ids.length === 0) {
        list.innerHTML = '<p class="status-msg">No orders yet. Buy a listing to create one.</p>';
        return;
      }
      list.innerHTML = '';
      for (const id of ids) {
        const state = await CRYPTO.getOrderState(id);
        const row = document.createElement('div');
        row.className = 'order-row';
        row.onclick = () => navigate('#/order/' + id);
        row.innerHTML = `
          <code>${escapeHtml(id.slice(0, 16))}...</code>
          <span class="state state-${escapeHtml(state?.data?.state || 'unknown')}">${escapeHtml(state?.data?.state || '?')}</span>
          <span>${escapeHtml(state?.data?.currency || '')}</span>
        `;
        list.appendChild(row);
      }
    } catch (e) {
      list.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  async function renderOrder(orderId) {
    const detail = getEl('order-detail');
    const chat = getEl('order-chat');
    if (!detail) return;
    detail.innerHTML = '<p class="status-msg">Loading...</p>';

    try {
      const order = await API.getOrder(orderId);
      const data = order._orderData || {};
      const state = data.state || 'unknown';
      detail.innerHTML = `
        <div class="order-card">
          <div class="state state-${escapeHtml(state)}">${escapeHtml(state)}</div>
          <p>Order: <code>${escapeHtml(orderId.slice(0, 16))}...</code></p>
          <p>Version: ${order.version}</p>
          <p>Currency: ${escapeHtml(data.currency || '?')}</p>
          <p>Escrow: <code>${escapeHtml(data.escrow_address || 'pending')}</code></p>
          <div class="actions">
            ${state === 'shipped' ? `<button class="btn-primary" onclick="APP.confirm('${orderId}')">Confirm Receipt</button><button class="btn-danger" onclick="APP.dispute('${orderId}')">Dispute</button>` : ''}
            ${state === 'pending' ? `<button class="btn-danger" onclick="APP.cancel('${orderId}')">Cancel</button>` : ''}
            ${state === 'funded' ? `<button class="btn-primary" onclick="APP.ship('${orderId}')">Mark Shipped</button>` : ''}
            ${state === 'disputed' ? `<button class="btn-danger" onclick="APP.refund('${orderId}')">Request Refund</button>` : ''}
          </div>
        </div>
      `;

      if (chat) {
        const msgs = await API.getMessages(orderId);
        chat.innerHTML = '';
        if (msgs.length > 0) {
          const myHash = CRYPTO.hashPubkey(CRYPTO.getPubkeyHex());
          msgs.forEach(m => {
            const div = document.createElement('div');
            div.className = 'chat-msg ' + (m.sender_pubkey_hash === myHash ? 'mine' : 'theirs');
            div.innerHTML = `
              <div>${escapeHtml(m.body)}</div>
              <div class="time">${new Date(m.created_at * 1000).toLocaleTimeString()}</div>
            `;
            chat.appendChild(div);
          });
          chat.scrollTop = chat.scrollHeight;
        } else {
          chat.innerHTML = '<p style="color:var(--text-dim);font-size:0.9em;">No messages yet</p>';
        }
      }
    } catch (e) {
      detail.innerHTML = `<p class="status-msg error">${escapeHtml(e.message)}</p>`;
    }
  }

  async function confirm(orderId) {
    try { await API.confirmOrder(orderId); renderOrder(orderId); }
    catch (e) { alert('Error: ' + e.message); }
  }

  async function ship(orderId) {
    try { await API.shipOrder(orderId); renderOrder(orderId); }
    catch (e) { alert('Error: ' + e.message); }
  }

  async function dispute(orderId) {
    try { await API.disputeOrder(orderId); renderOrder(orderId); }
    catch (e) { alert('Error: ' + e.message); }
  }

  async function cancel(orderId) {
    if (!confirm('Cancel this order?')) return;
    try { await API.cancelOrder(orderId); renderOrder(orderId); }
    catch (e) { alert('Error: ' + e.message); }
  }

  async function refund(orderId) {
    if (!confirm('Request refund?')) return;
    try { await API.refundOrder(orderId); renderOrder(orderId); }
    catch (e) { alert('Error: ' + e.message); }
  }

  async function sendMessage() {
    const input = getEl('chat-input');
    const orderId = window.location.hash.replace('#/order/', '');
    if (!input?.value.trim() || !orderId) return;
    const msg = input.value.trim();
    input.value = '';
    try {
      await API.sendMessage(orderId, msg);
      renderOrder(orderId);
    } catch (e) {
      alert('Send failed: ' + e.message);
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  async function init() {
    window.addEventListener('hashchange', () => navigate(window.location.hash));
    await CRYPTO.initWasm().catch(() => {});
    if (!CRYPTO.getPubkey()) {
      navigate(window.location.hash || '#/unlock');
    } else {
      navigate(window.location.hash || '#/');
    }
  }

  setInterval(() => {
    const hash = window.location.hash;
    if (hash.startsWith('#/order/')) {
      renderOrder(hash.replace('#/order/', ''));
    }
  }, 30000);

  document.addEventListener('DOMContentLoaded', init);
  if (document.readyState !== 'loading') init();

  return {
    handlePasswordSubmit, login: () => navigate('#/unlock'), logout, navigate,
    renderHome, renderListing, renderOrders, renderOrder,
    createListing, search, buy,
    confirm, ship, dispute, cancel, refund, sendMessage,
  };
})();
