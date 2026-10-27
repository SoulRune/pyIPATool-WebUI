// Escape everything from the network before it goes into innerHTML.
function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"'`]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;',
  }[c]));
}

// "App Store 2.2" next to a version whose Info.plist says otherwise (2.2.1).
function storeBadge(storeVersion, version) {
  if (!storeVersion || String(storeVersion) === String(version || '')) return '';
  return ` <span class="badge-store" title="The version as the App Store shows it">App Store ${esc(storeVersion)}</span>`;
}

// Run async tasks with at most `limit` in flight. Loading metadata for every
// version at once used to fire hundreds of simultaneous requests at Apple.
async function mapLimit(items, limit, fn, onProgress) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      try {
        results[index] = { status: 'fulfilled', value: await fn(items[index], index) };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
      done += 1;
      if (onProgress) onProgress(done, items.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

class IPAToolUI {
  constructor() {
    this.loginForm = document.querySelector('#login-form');
    this.logoutButton = document.querySelector('#logout-button');
    this.accountBox = document.querySelector('#account-info');
    this.accountsBox = document.querySelector('#accounts-box');
    this.accountsList = document.querySelector('#accounts-list');
    this.addAccountButton = document.querySelector('#add-account-button');
    this.accountsToggle = document.querySelector('#accounts-toggle');
    this.accountsCurrent = document.querySelector('#accounts-current');
    this.accountFields = this.accountBox?.querySelectorAll('[data-field]') || [];
    this.toast = document.querySelector('#toast');
    this.sections = document.querySelectorAll('#app-finder-section, #versions-section');

    this.baseUrl = window.APP_BASE_URL || '';
    if (this.baseUrl === '/') {
      this.baseUrl = '';
    } else if (this.baseUrl.endsWith('/') && this.baseUrl.length > 1) {
      this.baseUrl = this.baseUrl.slice(0, -1);
    }

    this.authCodeField = document.querySelector('#auth-code-field');
    this.authCodeMessage = document.querySelector('#auth-code-message');
    this.authCodeInput = this.authCodeField ? this.authCodeField.querySelector('input') : null;
  this.authModal = document.querySelector('#auth-modal');
  this.authModalForm = document.querySelector('#auth-modal-form');
  this.authModalMessage = document.querySelector('#auth-modal-message');
  this.authModalError = document.querySelector('#auth-modal-error');
  this.authModalInput = document.querySelector('#auth-modal-input');
  this.authModalCancel = document.querySelector('#auth-modal-cancel');
  this.pendingCredentials = null;

    this.currentAppId = null;
    this.currentBundleId = null;
    this.currentPlatform = '';

    this.tabs = document.querySelectorAll('.tab-btn');
    this.tabContents = document.querySelectorAll('.tab-content');
    this.searchForm = document.querySelector('#search-form');
    this.directLookupForm = document.querySelector('#direct-lookup-form');
    this.searchResults = document.querySelector('#search-results');
    this.versionsSection = document.querySelector('#versions-section');
    this.versionsList = document.querySelector('#versions-list');
    this.appTitle = document.querySelector('#app-title');
    this.appSubtitle = document.querySelector('#app-subtitle');
    this.communityFallbackCheckbox = document.querySelector('#community-fallback-checkbox');
    this.directCommunityFallbackCheckbox = document.querySelector('#direct-community-fallback-checkbox');
    this.currentCommunityFallback = false;
    this.downloadProgress = document.querySelector('#download-progress');
    this.downloadProgressText = document.querySelector('#download-progress-text');
    this.downloadProgressFilename = document.querySelector('#download-progress-filename');
  }

  // Always send the session cookie (older Safari defaulted fetch() to
  // credentials: 'omit').
  request(url, options = {}) {
    return fetch(url, { credentials: 'same-origin', ...options });
  }

  apiUrl(path) {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${this.baseUrl}${normalizedPath}`;
  }

  toggleAuthCode(show) {
    if (!this.authCodeField) {
      return;
    }
    this.authCodeField.hidden = !show;
    if (this.authCodeMessage) {
      this.authCodeMessage.hidden = !show;
    }
    if (!show && this.authCodeInput) {
      this.authCodeInput.value = '';
    }
    if (show && this.authCodeInput) {
      this.authCodeInput.focus();
    }
  }

  init() {
    // Hide versions section on initial load
    if (this.versionsSection) {
      this.versionsSection.hidden = true;
    }

    this.loginForm?.addEventListener('submit', (event) => {
      event.preventDefault();
      this.handleLogin();
    });

    this.logoutButton?.addEventListener('click', () => this.handleLogout());
    document.querySelector('#clear-cache-button')?.addEventListener('click', async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const response = await this.request(this.apiUrl('/api/cache/clear'), {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Failed');
        this.showToast(`Cache cleared (${payload.cleared} entr${payload.cleared === 1 ? 'y' : 'ies'})`);
      } catch (error) {
        this.showToast(error.message || 'Failed to clear the cache', true);
      } finally {
        button.disabled = false;
      }
    });
    // Show/hide the password (the eye button inside the field).
    document.querySelectorAll('[data-password-toggle]').forEach((button) => {
      button.addEventListener('click', () => {
        const input = button.parentElement?.querySelector('input');
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        button.setAttribute('aria-pressed', show ? 'true' : 'false');
        button.title = show ? 'Hide password' : 'Show password';
        button.setAttribute('aria-label', button.title);
        input.focus();
      });
    });
    this.addAccountButton?.addEventListener('click', () => this.handleAddAccount());
    this.accountsList?.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-account-action]');
      if (button) this.handleAccountAction(button.dataset.accountAction, button.dataset.accountId);
    });
    // Hover unfolds the menu (CSS); a click pins it open / closes it, which is
    // also how it opens on touch screens.
    this.accountsToggle?.addEventListener('click', (event) => {
      event.stopPropagation();
      this.setAccountsMenuOpen(!this.accountsBox.classList.contains('open'));
    });
    document.addEventListener('click', (event) => {
      if (this.accountsBox && !this.accountsBox.contains(event.target)) this.setAccountsMenuOpen(false);
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && this.accountsBox?.classList.contains('open')) {
        this.setAccountsMenuOpen(false);
        this.accountsToggle?.focus();
      }
    });

    this.authModalForm?.addEventListener('submit', (event) => {
      event.preventDefault();
      this.handleAuthModalSubmit();
    });

    this.authModalCancel?.addEventListener('click', () => {
      this.hideAuthCodeModal();
      this.pendingCredentials = null;
    });

    this.tabs?.forEach(tab => {
      tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
    });

    // Show the Apple TV hint only when that platform is selected
    const platformSelect = document.querySelector('#platform-select');
    const platformHint = document.querySelector('#platform-hint');
    if (platformSelect && platformHint) {
      platformSelect.addEventListener('change', (e) => {
        platformHint.hidden = e.target.value !== 'appletv';
      });
    }

    this.searchForm?.addEventListener('submit', (event) => {
      event.preventDefault();
      this.handleSearch();
    });

    this.directLookupForm?.addEventListener('submit', (event) => {
      event.preventDefault();
      this.handleDirectLookup();
    });

    this.refreshAccountState();
  }

  switchTab(tabName) {
    this.tabs.forEach(tab => {
      tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    this.tabContents.forEach(content => {
      content.classList.toggle('active', content.id === `${tabName}-tab`);
    });
    
    // Hide versions section when switching tabs
    if (this.versionsSection) {
      this.versionsSection.hidden = true;
    }
    
    // Clear search results when switching away from search tab
    if (tabName !== 'search' && this.searchResults) {
      this.searchResults.hidden = true;
    }
  }

  setLoggedIn(isLoggedIn) {
    const accountExtra = document.querySelector('#account-extra');
    if (accountExtra) accountExtra.hidden = !isLoggedIn; // the sign-in form has its own certificate hint
    if (this.loginForm) {
      this.loginForm.hidden = isLoggedIn;
      if (isLoggedIn) {
        this.loginForm.style.display = 'none';
      } else {
        this.loginForm.style.removeProperty('display');
      }
    }
    if (this.logoutButton) {
      this.logoutButton.hidden = !isLoggedIn;
    }
    if (this.accountBox) {
      this.accountBox.hidden = !isLoggedIn;
    }
    this.sections.forEach((section) => {
      if (section.id === 'app-finder-section') {
        section.hidden = !isLoggedIn;
      } else if (section.id === 'versions-section') {
        // Always hide versions section when logging in/out
        section.hidden = true;
      }
    });
    if (!isLoggedIn) {
      this.clearAccountFields();
      this.toggleAuthCode(false);
    }
    this.refreshAccounts();
  }

  // -- several saved sign-ins ------------------------------------------------

  setAccountsMenuOpen(open) {
    if (!this.accountsBox) return;
    this.accountsBox.classList.toggle('open', open);
    this.accountsToggle?.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  async refreshAccounts() {
    if (!this.accountsBox || !this.accountsList) return;
    let accounts = [];
    let max = 1;
    try {
      const response = await this.request(this.apiUrl('/api/accounts'));
      if (response.ok) {
        const payload = await response.json();
        accounts = payload.accounts || [];
        max = payload.max || 1;
      }
    } catch (error) {
      console.error(error);
    }
    const active = accounts.find(a => a.active);
    const main = (a) => a.name || a.email;
    this.accountsList.innerHTML = accounts.map(a => {
      const body = `<span class="account-main">${esc(main(a))}</span>`
        + `${a.name ? `<span class="account-sub">${esc(a.email)}</span>` : ''}`
        + `${a.storeFront ? `<span class="account-sub account-store" title="App Store region of this Apple ID">Storefront ${esc(a.storeFront)}</span>` : ''}`;
      if (a.active) {
        return `<li><div class="account-row is-active" title="Signed in">${body}</div></li>`;
      }
      return `<li><button type="button" class="account-row" data-account-action="switch" data-account-id="${esc(a.id)}" title="Switch to ${esc(a.email)}">${body}</button>`
        + `<button type="button" class="account-forget" data-account-action="forget" data-account-id="${esc(a.id)}" title="Forget this saved sign-in" aria-label="Forget ${esc(a.email)}">✕</button></li>`;
    }).join('');
    if (this.accountsCurrent) {
      this.accountsCurrent.textContent = active ? main(active) : `Saved accounts (${accounts.length})`;
      this.accountsCurrent.title = active ? active.email : '';
    }
    if (this.addAccountButton) {
      const full = accounts.length >= max;
      this.addAccountButton.disabled = full;
      this.addAccountButton.title = full ? `Up to ${max} sign-ins - forget one first` : 'Keep this sign-in and sign in with another Apple ID';
    }
    // Signed in: always (there is something to add). Signed out: only if there
    // are saved sign-ins to switch to.
    this.accountsBox.hidden = !active && accounts.length === 0;
    if (this.accountsBox.hidden) this.setAccountsMenuOpen(false);
  }

  async handleAddAccount() {
    this.setAccountsMenuOpen(false);
    if (this.loginForm && !this.loginForm.hidden) {
      // Signed out already: the form below is where the next account goes.
      this.loginForm.querySelector('input[name="email"]')?.focus();
      return;
    }
    try {
      const response = await this.request(this.apiUrl('/api/accounts/add'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      if (!response.ok) throw new Error((await response.json()).error || 'Failed');
      this.showToast('Sign in with another Apple ID - the current one stays saved');
      this.setLoggedIn(false);
    } catch (error) {
      this.showToast(error.message || 'Failed', true);
    }
  }

  async handleAccountAction(action, id) {
    if (!id) return;
    if (action === 'switch') this.setAccountsMenuOpen(false);
    if (action === 'forget' && !confirm('Forget this saved sign-in? Signing in again needs the password (and maybe a code).')) return;
    try {
      const response = await this.request(this.apiUrl(`/api/accounts/${action === 'switch' ? 'switch' : 'forget'}`), {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Failed');
      if (action === 'switch' && payload.account) {
        this.updateAccountBox(payload.account);
        this.setLoggedIn(true);
        this.showToast(`Switched to ${payload.account.email}`);
      } else {
        this.refreshAccounts();
      }
    } catch (error) {
      this.showToast(error.message || 'Failed', true);
    }
  }

  clearAccountFields() {
    this.accountFields.forEach((node) => {
      node.textContent = 'N/A';
    });
  }

  async refreshAccountState() {
    try {
      const response = await this.request(this.apiUrl('/api/account'));
      const payload = response.ok ? await response.json() : null;
      if (!payload || !payload.account) {
        this.setLoggedIn(false);
        return;
      }
      this.updateAccountBox(payload.account);
      this.setLoggedIn(true);
    } catch (error) {
      console.error(error);
      this.setLoggedIn(false);
    }
  }

  updateAccountBox(account) {
    if (!account) {
      this.setLoggedIn(false);
      return;
    }
    this.accountFields.forEach((node) => {
      const field = node.dataset.field;
      node.textContent = account?.[field] ?? 'N/A';
    });
  }

  async handleLogin() {
    if (!this.loginForm) {
      return;
    }

    const entries = Object.fromEntries(new FormData(this.loginForm).entries());
    const credentials = {
      email: entries.email || '',
      password: entries.password || '',
    };
    if (entries.authCode) {
      credentials.authCode = entries.authCode;
    }

    this.pendingCredentials = { ...credentials };
    await this.performLogin(credentials);
  }

  async performLogin(credentials) {
    const baseCredentials = {
      email: credentials.email || '',
      password: credentials.password || '',
    };
    const payload = { ...credentials };
    if (payload.authCode) {
      payload.authCode = String(payload.authCode).replace(/\s+/g, '');
    } else {
      delete payload.authCode;
    }

    this.setLoginBusy(true);
    this.setLoginError('');
    try {
      const response = await this.request(this.apiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      if (!response.ok) {
        if (response.status === 401 && result.authCodeRequired) {
          this.pendingCredentials = baseCredentials;
          if (credentials.authCode) {
            // A code was sent and Apple asks again: it didn't accept it.
            throw new Error("Apple didn't accept the sign-in. The code may be wrong or expired - or the password is wrong (Apple reports both the same way). Check the password and request a new code.");
          }
          this.showAuthCodeModal(result.error || 'Verification code required');
          return;
        }
        throw new Error(result.error || 'Login failed');
      }

      this.pendingCredentials = null;
      this.toggleAuthCode(false);
      this.hideAuthCodeModal();
      if (this.loginForm) {
        this.loginForm.reset();
      }
      this.showToast('Signed in successfully');
      this.updateAccountBox(result.account);
      this.setLoggedIn(true);
    } catch (error) {
      if (credentials.authCode) {
        this.pendingCredentials = baseCredentials;
        this.showAuthCodeModal(error.message || 'Login failed');
        if (this.authModalError) {
          this.authModalError.textContent = error.message || 'Login failed';
          this.authModalError.hidden = false;
        }
      } else {
        this.pendingCredentials = null;
        // Stays visible under the form until the next attempt: a sign-in
        // can take up to a minute, a toast is easy to miss.
        this.setLoginError(error.message || 'Login failed');
      }
      this.showToast(error.message || 'Login failed', true);
    } finally {
      this.setLoginBusy(false);
    }
  }

  setLoginBusy(busy) {
    const buttons = [
      this.loginForm?.querySelector('button[type="submit"]'),
      this.authModalForm?.querySelector('button[type="submit"]'),
    ].filter(Boolean);
    buttons.forEach((button) => {
      if (busy) {
        if (!button.dataset.label) button.dataset.label = button.textContent;
        button.textContent = 'Signing in... (can take up to a minute)';
        button.disabled = true;
      } else {
        if (button.dataset.label) button.textContent = button.dataset.label;
        button.disabled = false;
      }
    });
  }

  setLoginError(message) {
    const box = document.querySelector('#login-error');
    if (!box) return;
    box.textContent = message || '';
    box.hidden = !message;
  }

  handleAuthModalSubmit() {
    if (!this.pendingCredentials) {
      this.showToast('Please start the sign-in flow again', true);
      this.hideAuthCodeModal();
      return;
    }

    const code = this.authModalInput?.value.trim();
    if (!code) {
      if (this.authModalError) {
        this.authModalError.textContent = 'Enter the six-digit verification code to continue.';
        this.authModalError.hidden = false;
      }
      this.authModalInput?.focus();
      return;
    }

    if (this.authModalError) {
      this.authModalError.hidden = true;
    }

    const nextAttempt = {
      ...this.pendingCredentials,
      authCode: code,
    };

    if (this.authCodeInput) {
      this.authCodeInput.value = code;
    }

    this.hideAuthCodeModal();
    this.pendingCredentials = nextAttempt;
    this.performLogin(nextAttempt);
  }

  async handleLogout() {
    try {
      await this.request(this.apiUrl('/api/auth/logout'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
    } finally {
      this.showToast('Signed out');
      this.setLoggedIn(false);
    }
  }

  async handleSearch() {
    const formData = this.serializeForm(this.searchForm);
    const params = new URLSearchParams();
    if (formData.term) params.set('term', formData.term);
    if (formData.limit) params.set('limit', formData.limit);
    if (formData.platform) params.set('platform', formData.platform);
    if (formData.country) params.set('country', formData.country);
    this.lastSearchCountry = (formData.country || '').toLowerCase();
    this.lastSearchPlatform = formData.platform || '';

    try {
      const response = await this.request(`${this.apiUrl('/api/search')}?${params.toString()}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'Search failed');
      }
      this.renderSearchResults(payload.results || []);
    } catch (error) {
      this.showToast(error.message || 'Search failed', true);
    }
  }

  renderSearchResults(results) {
    if (!this.searchResults) return;
    
    if (results.length === 0) {
      this.searchResults.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔍</div><p>No apps found</p></div>';
      this.searchResults.hidden = false;
      return;
    }

    this.searchResults.innerHTML = results.map(app => `
      <div class="app-card" data-app-id="${esc(app.trackId)}" data-bundle-id="${esc(app.bundleId)}" data-app-name="${esc(app.trackName || '')}">
        <div class="app-card-header">
          <div>
            <h3 class="app-card-title">${esc(app.trackName || 'Unknown')}</h3>
            <div class="app-card-meta">
              <span>📦 ${esc(app.bundleId || 'N/A')}</span>
              <span>🏷️ v${esc(app.version || 'N/A')}</span>
              ${app.price > 0 ? `<span>💰 $${esc(app.price)}</span>` : '<span class="badge">Free</span>'}
            </div>
            <div style="margin-top: 0.5rem;">
              <span class="copy-code" data-copy="${esc(app.trackId)}" title="Click to copy App ID">
                <span class="copy-icon">🆔</span>
                <span>${esc(app.trackId)}</span>
              </span>${/^\d+$/.test(String(app.trackId || '')) ? `
              <a class="appstore-chip" href="https://itunes.apple.com/${this.lastSearchCountry ? esc(this.lastSearchCountry) + '/' : ''}app/id${esc(app.trackId)}" target="_blank" rel="noopener noreferrer" title="Open in App Store">🛍️ App Store</a>` : ''}
            </div>
          </div>
        </div>
      </div>
    `).join('');

    this.searchResults.querySelectorAll('.app-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.copy-code') || e.target.closest('.appstore-chip')) {
          return;
        }
        
        const appId = card.dataset.appId;
        const bundleId = card.dataset.bundleId;
        // The checkboxes as they are now, not as they were at search time.
        const options = this.serializeForm(this.searchForm);
        this.mergeCatalogs = !!options.mergeCatalogs;
        this.currentAppName = card.dataset.appName || '';
        this.loadAppVersions(appId, bundleId, null, this.lastSearchPlatform, !!options.communityFallback,
          !!options.catalogFirst);
      });
    });

    this.searchResults.querySelectorAll('.copy-code').forEach(code => {
      code.addEventListener('click', (e) => {
        e.stopPropagation();
        const text = code.dataset.copy;
        navigator.clipboard.writeText(text).then(() => {
          this.showToast(`Copied: ${text}`);
        }).catch(() => {
          this.showToast('Failed to copy', true);
        });
      });
    });

    this.searchResults.hidden = false;
  }

  async handleDirectLookup() {
    const formData = this.serializeForm(this.directLookupForm);
    if (!formData.appId && !formData.bundleId) {
      this.showToast('Please provide App ID or Bundle ID', true);
      return;
    }
    this.mergeCatalogs = !!formData.mergeCatalogs;
    this.currentAppName = '';
    this.loadAppVersions(formData.appId, formData.bundleId, formData.externalVersionId, formData.platform,
      !!formData.communityFallback, !!formData.catalogFirst);
  }

  async loadAppVersions(appId, bundleId, externalVersionId = null, platform = '', communityFallback = false, catalogFirst = false) {
    this.currentAppId = appId;
    this.currentBundleId = bundleId;
    this.currentPlatform = platform || '';

    const communityFallbackEnabled = !!communityFallback;
    // "Private catalog first": the catalog's versions right away when it has
    // this app (no request to Apple); otherwise Apple as usual.
    if (catalogFirst && !externalVersionId) {
      const shown = await this.loadAppVersionsFromCatalog(appId, bundleId, externalVersionId, platform, communityFallback);
      if (shown) return;
    }

    const params = new URLSearchParams();
    if (appId) params.set('appId', appId);
    if (bundleId) params.set('bundleId', bundleId);
    if (externalVersionId) params.set('externalVersionId', externalVersionId);
    if (this.currentPlatform) params.set('platform', this.currentPlatform);

    try {
      this.versionsSection.hidden = false;
      this.versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div></div>';
      this.appTitle.textContent = 'Loading...';
      this.appSubtitle.textContent = '';

      const response = await this.request(`${this.apiUrl('/api/versions')}?${params.toString()}`);
      const data = await response.json();
      if (!response.ok) {
        const failureType = data.metadata?.failureType;
        const marketAllowed = data.metadata?.['m-allowed'];

        // Apple Arcade: not supported - show what the community database
        // knows, read-only (version ids only), regardless of the toggle.
        if (data.arcade) {
          await this.loadAppVersionsFromCommunity(appId, bundleId, data.error || '', data.arcadeLatestVersionId || '');
          return;
        }

        // No license: always the license flow, never the community fallback.
        if (data.licenseRequired || failureType === '9610' || (data.error && data.error.includes('license'))) {
          const shouldAcquire = confirm('A license is required to view versions for this app. Would you like to acquire it now?');
          if (shouldAcquire) {
            await this.acquireLicenseAndRetry(appId, bundleId, externalVersionId, this.currentPlatform);
            return;
          }
          throw new Error(data.error || 'Failed to load versions');
        }

        // Apple's generic refusal (5002, m-allowed false): only then try Timbrd.
        if (communityFallbackEnabled && failureType === '5002' && marketAllowed === false) {
          this.showToast('Apple refused this app (not a licensing issue) - trying the community database instead...');
          await this.loadAppVersionsFromCommunity(appId, bundleId);
          return;
        }

        throw new Error(data.error || 'Failed to load versions');
      }

      if (data.arcadeProbeVersionId) {
        this.showToast(`Apple Arcade: Apple answered the version list only when asked for version ${data.arcadeProbeVersionId} - some versions may still refuse to download`);
      }
      const versions = Array.isArray(data.externalVersionIdentifiers) ? data.externalVersionIdentifiers : [];
      const catalogEntries = this.mergeCatalogs && !externalVersionId ? await this.fetchCatalogEntries(appId, bundleId) : [];
      await this.loadAndRenderVersions(versions, catalogEntries);
    } catch (error) {
      this.showToast(error.message || 'Failed to load versions', true);
      this.versionsList.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><p>${esc(error.message)}</p></div>`;
      this.versionsSection.hidden = true;
    }
  }

  // "Name / bundle id | N versions | source", the same for every source; a
  // name not known yet (Direct Lookup) is filled in from the App Store.
  setVersionsHeader(count, note = '') {
    this.versionsHeader = { count, note };
    this.renderVersionsHeader();
    if (!this.currentAppName) this.fillAppName();
  }

  renderVersionsHeader() {
    const { count, note } = this.versionsHeader || { count: 0, note: '' };
    this.appTitle.textContent = this.currentAppName || 'App Versions';
    this.appSubtitle.textContent = [this.currentBundleId || (this.currentAppId ? `id${this.currentAppId}` : ''),
      `${count} version${count === 1 ? '' : 's'}`, note].filter(Boolean).join(' | ');
  }

  async fillAppName() {
    const key = `${this.currentAppId}|${this.currentBundleId}`;
    const params = new URLSearchParams();
    if (this.currentAppId) params.set('appId', this.currentAppId);
    if (this.currentBundleId) params.set('bundleId', this.currentBundleId);
    try {
      const response = await this.request(`${this.apiUrl('/api/app-info')}?${params.toString()}`);
      const data = await response.json();
      if (!response.ok || key !== `${this.currentAppId}|${this.currentBundleId}`) return;
      if (data.name) this.currentAppName = data.name;
      if (data.bundleId && !this.currentBundleId) this.currentBundleId = data.bundleId;
      this.renderVersionsHeader();
    } catch (error) {
      // the header keeps the id
    }
  }

  async loadAppVersionsFromCatalog(appId, bundleId, externalVersionId, platform, communityFallback) {
    const params = new URLSearchParams();
    if (appId) params.set('appId', appId);
    if (bundleId) params.set('bundleId', bundleId);
    this.versionsSection.hidden = false;
    this.versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div></div>';
    this.appTitle.textContent = 'Loading...';
    this.appSubtitle.textContent = '';
    let data;
    try {
      const response = await this.request(`${this.apiUrl('/api/versions/catalog')}?${params.toString()}`);
      data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to read the private catalog');
    } catch (error) {
      this.showToast(`Private catalog: ${error.message || 'unavailable'} - asking Apple`, true);
      return false;
    }
    const entries = Array.isArray(data.entries) ? data.entries : [];
    if (!data.found || !entries.length) {
      this.showToast('Not in the private catalog - asking Apple');
      return false;
    }
    if (!this.currentBundleId && data.bundleId) this.currentBundleId = data.bundleId;
    this.setVersionsHeader(entries.length, 'private catalog');
    this.renderCommunityVersions(entries, false);
    const updated = data.updatedAt ? ` (updated ${esc(String(data.updatedAt).slice(0, 10))})` : '';
    this.versionsList.insertAdjacentHTML('afterbegin',
      `<div class="notice-info" role="note">📚 From the private catalog${updated} - Apple wasn't asked, so versions released since then aren't here.
        <button type="button" class="secondary small" id="ask-apple-button">Ask Apple</button></div>`);
    this.versionsList.querySelector('#ask-apple-button')?.addEventListener('click', () => {
      this.loadAppVersions(appId, bundleId, externalVersionId, platform, communityFallback, false);
    });
    return true;
  }

  async loadAppVersionsFromCommunity(appId, bundleId, arcadeNotice = '', currentVersionId = '') {
    const params = new URLSearchParams();
    if (appId) params.set('appId', appId);
    if (bundleId) params.set('bundleId', bundleId);

    try {
      this.versionsSection.hidden = false;
      this.versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div></div>';
      this.appTitle.textContent = 'Loading...';
      this.appSubtitle.textContent = '';

      let entries = [];
      let communityError = '';
      let communitySource = '';
      try {
        const response = await this.request(`${this.apiUrl('/api/versions/community')}?${params.toString()}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to load community versions');
        entries = Array.isArray(data.entries) ? data.entries : [];
        communitySource = data.source || '';
      } catch (error) {
        if (!currentVersionId) throw error;
        communityError = error.message || 'Failed to load community versions';
      }

      // Apple Arcade: the current version is the one Apple serves - put it
      // first and keep its download buttons; the rest stays read-only.
      if (currentVersionId) {
        const current = entries.find(e => String(e.externalVersionId) === String(currentVersionId));
        entries = entries.filter(e => e !== current);
        entries.unshift(Object.assign({}, current || { externalVersionId: currentVersionId, bundleVersion: 'current' }, { current: true }));
      }

      this.setVersionsHeader(entries.length, `community catalogs (${communitySource || 'timbrd'})`);
      this.renderCommunityVersions(entries, false);
      if (arcadeNotice) {
        const title = '🕹️ Apple Arcade.';
        const extra = communityError ? ` (Community database: ${communityError})` : '';
        this.versionsList.insertAdjacentHTML('afterbegin',
          `<div class="notice-warning" role="note"><strong>${title}</strong> ${esc(arcadeNotice + extra)}</div>`);
      }
    } catch (error) {
      this.showToast(error.message || 'Failed to load community versions', true);
      this.versionsList.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><p>${esc(error.message)}</p></div>`;
    }
  }

  renderCommunityVersions(entries, readOnly = false, target = null) {
    const container = target || this.versionsList;
    if (entries.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><p>No versions found in the community database</p></div>';
      return;
    }

    container.innerHTML = entries.map(entry => {
      const sizeText = entry.size ? `${(entry.size / 1024 / 1024).toFixed(2)} MB` : 'Unknown';
      const fromCatalog = String(entry.source || '').startsWith('catalog');
      const dateText = entry.createdAt ? (fromCatalog ? String(entry.createdAt).slice(0, 10) : entry.createdAt)
        : (entry.releaseDateDisplay || 'Unknown');
      const catalogDetails = [['Developer', entry.artist], ['Genre', entry.genre], ['Age Rating', entry.ageRating],
        ['Copyright', entry.copyright]].filter(([, v]) => v).map(([k, v]) => `<dt>${k}:</dt><dd>${esc(v)}</dd>`).join('');
      const bundleIdText = this.currentBundleId || 'N/A';
      return `
        <div class="version-card" data-version-id="${esc(entry.externalVersionId)}">
          <div class="version-header">
            <div class="version-basic">
              <div><strong>Version:</strong> ${esc(entry.bundleVersion || 'unknown')}${storeBadge(entry.storeVersion, entry.bundleVersion)}${entry.current ? ' <span class="badge-current">current version</span>' : ''}${entry.appleRefused ? ' <span class="badge-unknown" title="Apple didn\'t describe this version for this account - it may still download">not described by Apple</span>' : ''}${entry.status === 'lost' ? ' <span class="badge-lost" title="Apple refused this version to the catalog\'s account - it may still download">lost</span>' : (entry.status === 'unknown' ? ' <span class="badge-unknown">unknown</span>' : '')}</div>
              <div><strong>Build:</strong> ${esc(entry.build || 'N/A')}</div>
              <div><strong>Size:</strong> ${esc(sizeText)}</div>
              <div><strong>${fromCatalog ? 'Released' : 'Seen'}:</strong> ${esc(dateText)}</div>
              ${entry.minimumOs ? `<div title="Minimum OS version, recorded by the collector"><strong>Requires:</strong> iOS ${esc(entry.minimumOs)}+</div>` : ''}
            </div>
            <span class="expand-icon">▼</span>
          </div>
          <div class="version-details">
            <dl>
              <dt>Version ID:</dt>
              <dd>
                <span class="copy-code" data-copy="${esc(entry.externalVersionId)}" title="Click to copy Version ID">
                  <span>${esc(entry.externalVersionId)}</span>
                </span>
              </dd>
              <dt>Bundle ID:</dt><dd>${esc(bundleIdText)}</dd>
              ${entry.storeVersion ? `<dt>App Store:</dt><dd>${esc(entry.storeVersion)}</dd>` : ''}
              ${catalogDetails}
              ${entry.status === 'lost' ? `<dt>Catalog:</dt><dd>Apple refused this version to the catalog's account${entry.checkedAt ? ` (checked ${esc(String(entry.checkedAt).slice(0, 10))})` : ''} - Apple's answer can change, so it may still download.</dd>` : ''}
              ${(entry.alsoIn || []).length ? `<dt>Also listed in:</dt><dd>${esc(entry.alsoIn.join(', '))}</dd>` : ''}
              <dt>Source:</dt><dd>${entry.current ? 'Apple (current version)' : (entry.source === 'catalog' ? 'Private catalog' : entry.source === 'catalog-external' ? 'External catalog' : `Community catalog (${esc(entry.source || 'timbrd')}) - not run or endorsed by Apple`)}</dd>
            </dl>
            ${readOnly && !entry.current ? '' : `<div class="version-actions">
              <button type="button" class="download-version-btn" data-version-id="${esc(entry.externalVersionId)}">Download IPA</button>
              <button type="button" class="save-server-btn secondary" data-version-id="${esc(entry.externalVersionId)}" title="Save directly on the machine running the server, skip the browser download entirely">💾 Save on server</button>
              <button type="button" class="install-ota-btn secondary" data-version-id="${esc(entry.externalVersionId)}" title="Install straight onto this iPhone/iPad over the network (itms-services)">📲 Install on device</button>
            </div>`}
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('.version-card').forEach(card => {
      const header = card.querySelector('.version-header');
      header.addEventListener('click', () => {
        card.classList.toggle('expanded');
      });

      const downloadBtn = card.querySelector('.download-version-btn');
      downloadBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.downloadVersion(downloadBtn.dataset.versionId, false);
      });
      const saveServerBtn = card.querySelector('.save-server-btn');
      saveServerBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.downloadVersionToServer(saveServerBtn.dataset.versionId, false);
      });
      const otaBtn = card.querySelector('.install-ota-btn');
      otaBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.startDownloadJob(otaBtn.dataset.versionId, false, false, true);
      });
      const copyCode = card.querySelector('.copy-code');
      copyCode?.addEventListener('click', () => {
        const text = copyCode.dataset.copy;
        navigator.clipboard?.writeText(text).then(() => this.showToast(`Copied: ${text}`));
      });
    });
  }

  async acquireLicenseAndRetry(appId, bundleId, externalVersionId = null, platform = '') {
    try {
      this.showToast('Acquiring license...');
      
      const payload = {};
      if (appId) payload.appId = appId;
      if (bundleId) payload.bundleId = bundleId;

      const response = await this.request(this.apiUrl('/api/purchase'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to acquire license');
      }
      
      this.showToast('License acquired successfully');
      
      // Retry loading versions
      await this.loadAppVersions(appId, bundleId, externalVersionId, platform);
    } catch (error) {
      this.showToast(error.message || 'Failed to acquire license', true);
      this.versionsSection.hidden = true;
    }
  }

  async fetchCatalogEntries(appId, bundleId) {
    // Merged version catalogs (private catalog first, then Timbrd, bilin).
    const params = new URLSearchParams();
    if (appId) params.set('appId', appId);
    if (bundleId) params.set('bundleId', bundleId);
    try {
      const response = await this.request(`${this.apiUrl('/api/versions/community')}?${params.toString()}`);
      const data = await response.json();
      return response.ok && Array.isArray(data.entries) ? data.entries : [];
    } catch (error) {
      return [];
    }
  }

  async loadAndRenderVersions(versionIds, catalogEntries = []) {
    // With "merge catalogs": versions only the catalogs know are asked about
    // too, and versions Apple doesn't describe stay listed (from the catalogs).
    const catalogById = new Map(catalogEntries.map(e => [String(e.externalVersionId), e]));
    // Newest first, as in the private catalog: version ids grow with each release.
    versionIds = Array.from(new Set([...versionIds.map(String), ...catalogById.keys()]))
      .filter(id => /^\d+$/.test(id))
      .sort((a, b) => Number(b) - Number(a));
    if (versionIds.length === 0) {
      this.versionsList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><p>No versions found</p></div>';
      this.versionsSection.hidden = true;
      return;
    }

    // Apps with a long history need many requests to Apple; show progress
    // instead of a bare spinner until every version's details are back.
    this.versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div><div class="hint" style="margin-top:1rem;">Loading version details...</div></div>';
    const progressHint = this.versionsList.querySelector('.hint');
    const metadataResults = await mapLimit(
      versionIds,
      4,
      (versionId) => this.fetchVersionMetadata(versionId),
      (done, total) => {
        if (progressHint) progressHint.textContent = `Loading version details... ${done} / ${total}`;
      },
    );
    
    const versions = metadataResults
      .map((result, index) => {
        if (result.status === 'fulfilled') {
          return { ...result.value, versionId: versionIds[index], catalog: catalogById.get(String(versionIds[index])) };
        }
        return null;
      })
      .filter(Boolean);
    // Versions Apple didn't describe but a catalog knows: keep them.
    const fromCatalogs = metadataResults
      .map((result, index) => (result.status === 'fulfilled' ? null : catalogById.get(String(versionIds[index]))))
      .filter(Boolean)
      .map(entry => ({ ...entry, appleRefused: true }));

    if (versions.length > 0 || fromCatalogs.length > 0) {
      const described = versions.find(v => v.itemName) || {};
      if (described.itemName) this.currentAppName = described.itemName;
      if (described.bundleId) this.currentBundleId = described.bundleId;
      const skipped = versionIds.length - versions.length - fromCatalogs.length;
      this.setVersionsHeader(versions.length, [fromCatalogs.length ? `${fromCatalogs.length} more from catalogs` : '',
        skipped > 0 ? `${skipped} not served by Apple (hidden)` : ''].filter(Boolean).join(' | '));
      this.renderVersionCards(versions);
      this.annotateWithCatalogs(versions);
      if (fromCatalogs.length) {
        this.versionsList.insertAdjacentHTML('beforeend',
          '<div class="catalog-extra"><h4 class="catalog-extra-title">Not described by Apple - from version catalogs</h4><div class="catalog-extra-list"></div></div>');
        this.renderCommunityVersions(fromCatalogs, false, this.versionsList.querySelector('.catalog-extra-list'));
      }
      this.versionsSection.hidden = false;
    } else {
      this.versionsList.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><p>No versions found</p></div>';
      this.versionsSection.hidden = true;
    }
  }

  async fetchVersionMetadata(versionId) {
    const params = new URLSearchParams();
    if (this.currentAppId) params.set('appId', this.currentAppId);
    if (this.currentBundleId) params.set('bundleId', this.currentBundleId);
    params.set('versionId', versionId);

    const response = await this.request(`${this.apiUrl('/api/version-metadata')}?${params.toString()}`);
    const data = await response.json();
    if (!response.ok) {
      // Many versions load at once: skip this one instead of prompting
      throw new Error(data.error || 'Failed to load metadata');
    }
    return data;
  }

  annotateWithCatalogs(versions) {
    // Cross-check: what the catalogs say about versions Apple described.
    versions.forEach(version => {
      const entry = version.catalog;
      if (!entry) return;
      const card = Array.from(this.versionsList.querySelectorAll('.version-card'))
        .find(c => c.dataset.versionId === String(version.versionId));
      const list = card && card.querySelector('.version-details dl');
      if (!list) return;
      const sources = [entry.source, ...(entry.alsoIn || [])].filter(Boolean).join(', ');
      const status = entry.status ? ` (${esc(entry.status)} in ${esc(entry.source)})` : '';
      list.insertAdjacentHTML('beforeend', `<dt>Catalogs:</dt><dd>${esc(sources)}${status}</dd>`);
    });
  }

  renderVersionCards(versions) {
    this.versionsList.innerHTML = versions.map((version, index) => {
      const fileSizeMB = (version.fileSize / (1024 * 1024)).toFixed(2);
      const releaseDate = version.releaseDateDisplay || (version.releaseDate
        ? new Date(version.releaseDate).toLocaleDateString()
        : 'Unknown');

      return `
        <div class="version-card" data-version-id="${esc(version.versionId)}" data-index="${index}">
          <div class="version-header">
            <div class="version-basic">
              <div><strong>Version:</strong> ${esc(version.displayVersion)}${storeBadge(version.storeVersion, version.displayVersion)}</div>
              <div><strong>Build:</strong> ${esc(version.buildNumber)}</div>
              <div><strong>Size:</strong> ${esc(fileSizeMB)} MB</div>
              <div><strong>Released:</strong> ${esc(releaseDate)}</div>
              ${version.minimumOsVersion ? `<div title="Minimum OS version, from this version's Info.plist"><strong>Requires:</strong> ${esc(version.minimumOsName || 'iOS')} ${esc(version.minimumOsVersion)}+</div>` : ''}
            </div>
            <span class="expand-icon">▼</span>
          </div>
          <div class="version-details">
            <dl>
              <dt>Version ID:</dt>
              <dd>
                <span class="copy-code" data-copy="${esc(version.versionId)}" title="Click to copy Version ID">
                  <span>${esc(version.versionId)}</span>
                </span>
              </dd>
              <dt>Bundle ID:</dt><dd>${esc(version.bundleId)}</dd>
              ${version.storeVersion ? `<dt>App Store:</dt><dd>${esc(version.storeVersion)}</dd>` : ''}
              <dt>Developer:</dt><dd>${esc(version.artistName)}</dd>
              <dt>Genre:</dt><dd>${esc(version.genre)}</dd>
              <dt>Age Rating:</dt><dd>${esc(version.ageRating)}</dd>
              <dt>Copyright:</dt><dd>${esc(version.copyright)}</dd>
            </dl>
            <div class="version-actions">
              <button type="button" class="download-version-btn" data-version-id="${esc(version.versionId)}">Download IPA</button>
              <button type="button" class="save-server-btn secondary" data-version-id="${esc(version.versionId)}" title="Save directly on the machine running the server, skip the browser download entirely">💾 Save on server</button>
              <button type="button" class="install-ota-btn secondary" data-version-id="${esc(version.versionId)}" title="Install straight onto this iPhone/iPad over the network (itms-services)">📲 Install on device</button>
            </div>
          </div>
        </div>
      `;
    }).join('');

    this.versionsList.querySelectorAll('.version-card').forEach(card => {
      const header = card.querySelector('.version-header');
      header.addEventListener('click', () => {
        card.classList.toggle('expanded');
      });

      const downloadBtn = card.querySelector('.download-version-btn');
      
      downloadBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.downloadVersion(card.dataset.versionId, false);
      });

      const saveServerBtn = card.querySelector('.save-server-btn');

      saveServerBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.downloadVersionToServer(card.dataset.versionId, false);
      });

      const otaBtn = card.querySelector('.install-ota-btn');
      otaBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.startDownloadJob(card.dataset.versionId, false, false, true);
      });
    });

    this.versionsList.querySelectorAll('.copy-code').forEach(code => {
      code.addEventListener('click', (e) => {
        e.stopPropagation();
        const text = code.dataset.copy;
        navigator.clipboard.writeText(text).then(() => {
          this.showToast(`Copied: ${text}`);
        }).catch(() => {
          this.showToast('Failed to copy', true);
        });
      });
    });
  }

  async downloadVersion(versionId, purchaseIfNeeded) {
    return this.startDownloadJob(versionId, purchaseIfNeeded, false);
  }

  // Saves into ~/Downloads/IPATool on the server (for browsers that can't
  // receive a download, such as iOS 6 Safari).
  async downloadVersionToServer(versionId, purchaseIfNeeded) {
    return this.startDownloadJob(versionId, purchaseIfNeeded, true);
  }

  async startDownloadJob(versionId, purchaseIfNeeded, saveToServerFolder, installOta = false) {
    const payload = {
      externalVersionId: versionId
    };
    if (this.currentAppId) payload.appId = this.currentAppId;
    if (this.currentBundleId) payload.bundleId = this.currentBundleId;
    if (this.currentPlatform) payload.platform = this.currentPlatform;
    if (purchaseIfNeeded) payload.purchaseIfNeeded = true;
    if (saveToServerFolder) payload.saveToServerFolder = true;

    try {
      this.showToast(saveToServerFolder ? 'Starting server-side download...' : 'Starting download...');
      this.showDownloadProgress('Preparing download...');

      // A background job on the server: poll its progress, then hand the file
      // to the browser as a plain download (or keep it on the server).
      const startResponse = await this.request(this.apiUrl('/api/download-jobs'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const startData = await startResponse.json();
      if (!startResponse.ok || !startData.jobId) {
        throw new Error(startData.error || 'Download failed');
      }

      await this.pollDownloadJob(startData.jobId, saveToServerFolder, installOta);
    } catch (error) {
      this.hideDownloadProgress();
      this.showToast(error.message || 'Download failed', true);
    }
  }

  pollDownloadJob(jobId, saveToServerFolder, installOta = false) {
    return new Promise((resolve) => {
      let filename = 'app.ipa';
      const poll = async () => {
        let job;
        try {
          const response = await this.request(this.apiUrl(`/api/download-jobs/${jobId}`));
          if (response.status === 404) {
            this.hideDownloadProgress();
            this.showToast('Download failed', true);
            resolve();
            return;
          }
          job = await response.json();
        } catch (error) {
          this.hideDownloadProgress();
          this.showToast('Download failed', true);
          resolve();
          return;
        }

        if (job.filename) filename = job.filename;

        if (job.status === 'error') {
          this.hideDownloadProgress();
          this.showToast(job.error || 'Download failed', true);
          resolve();
          return;
        }

        if (job.status === 'ready') {
          if (installOta && job.installUrl) {
            this.hideDownloadProgress();
            this.showOtaInstall(job, filename);
            resolve();
            return;
          }
          if (saveToServerFolder) {
            this.hideDownloadProgress();
            this.showToast(`Saved on server: ${job.serverPath || filename}`);
            resolve();
            return;
          }
          const fileUrl = this.apiUrl(`/api/download-jobs/${jobId}/file`);
          this.updateDownloadProgress('Saving file...', filename);
          this.fetchFileViaHiddenIframe(fileUrl);
          this.showManualDownloadLink(fileUrl, filename);
          setTimeout(() => {
            this.hideDownloadProgress();
            this.showToast(`Downloading: ${filename}`);
          }, 800);
          resolve();
          return;
        }

        if (job.phase === 'patching' || job.phase === 'finalizing') {
          // Downloaded; the server is adding metadata and the SINF (slow for big apps).
          let label = job.phase === 'patching' ? 'Patching package...' : 'Finalizing (adding signature)...';
          if (job.itemsTotal) {
            label += ` ${job.itemsDone} / ${job.itemsTotal} files`;
          }
          this.updateDownloadProgress(label, filename);
        } else if (job.bytesTotal) {
          const percent = Math.floor((job.bytesDone / job.bytesTotal) * 100);
          const done = (job.bytesDone / 1024 / 1024).toFixed(1);
          const total = (job.bytesTotal / 1024 / 1024).toFixed(1);
          this.updateDownloadProgress(`${percent}% (${done} MB / ${total} MB)`, filename);
        } else if (job.bytesDone) {
          this.updateDownloadProgress(`Downloading... ${(job.bytesDone / 1024 / 1024).toFixed(1)} MB`, filename);
        } else {
          this.updateDownloadProgress('Preparing download...', filename);
        }

        setTimeout(poll, 1500);
      };
      poll();
    });
  }

  fetchFileViaHiddenIframe(url) {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = url;
    document.body.appendChild(iframe);
    setTimeout(() => {
      iframe.remove();
    }, 60000);
  }

  // Some iOS browsers (Orion) don't save a file from the hidden iframe, and the
  // itms-services prompt is reliable only for a tap: offer real links too.
  minimumOsWarning(job) {
    if (!job.minimumOsVersion) return '';
    const needed = job.minimumOsVersion.split('.').map((n) => parseInt(n, 10) || 0);
    const match = /OS (\d+)_(\d+)(?:_(\d+))? like Mac OS X/.exec(navigator.userAgent || '');
    if (match) {
      const device = [match[1], match[2], match[3] || '0'].map((n) => parseInt(n, 10));
      for (let i = 0; i < Math.max(needed.length, device.length); i += 1) {
        const x = device[i] || 0;
        const y = needed[i] || 0;
        if (x !== y) {
          if (x < y) {
            return `This version needs iOS ${job.minimumOsVersion} or later, but this device runs iOS ${device.join('.')} - iOS will refuse to install it. `;
          }
          break;
        }
      }
    }
    return `Requires iOS ${job.minimumOsVersion}+. `;
  }

  showOtaInstall(job, filename) {
    const existing = document.querySelector('#manual-download-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'manual-download-banner';
    banner.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e293b;border:1px solid rgba(148,163,184,0.3);border-radius:12px;padding:0.85rem 1rem;box-shadow:0 10px 30px rgba(0,0,0,0.4);z-index:9998;width:calc(100vw - 2.5rem);max-width:420px;font-size:0.9rem;color:#f8fafc;box-sizing:border-box;';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = '✕';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.className = 'banner-close float-right';
    closeBtn.addEventListener('click', () => banner.remove());

    const link = document.createElement('a');
    link.href = job.installUrl;
    link.style.cssText = 'display:block;color:#60a5fa;font-weight:600;text-decoration:none;line-height:1.4;margin:0.2rem 0 0.4rem;';
    link.textContent = `📲 Tap to install ${filename}`;

    const note = document.createElement('div');
    note.style.cssText = 'color:rgba(226,232,240,0.75);line-height:1.35;font-size:0.8rem;';
    note.textContent = this.minimumOsWarning(job) + (job.otaNeedsHttps
      ? 'Served over HTTP: works on iOS 6; iOS 7.1+ needs HTTPS.'
      : '');

    banner.appendChild(closeBtn);
    banner.appendChild(link);
    if (note.textContent) banner.appendChild(note);
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 10 * 60 * 1000);

    try {
      window.location.href = job.installUrl;
    } catch (e) {
      // ignored: the visible link above is the fallback
    }
  }

  showManualDownloadLink(url, filename) {
    const existing = document.querySelector('#manual-download-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'manual-download-banner';
    banner.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e293b;border:1px solid rgba(148,163,184,0.3);border-radius:12px;padding:0.85rem 1rem;box-shadow:0 10px 30px rgba(0,0,0,0.4);z-index:9998;width:calc(100vw - 2.5rem);max-width:420px;font-size:0.9rem;color:#f8fafc;box-sizing:border-box;';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:0.75rem;margin-bottom:0.6rem;';

    const label = document.createElement('div');
    label.style.cssText = 'color:rgba(226,232,240,0.8);line-height:1.3;';
    label.textContent = "If the download didn't start automatically:";

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.textContent = '✕';
    closeBtn.className = 'banner-close';
    closeBtn.addEventListener('click', () => banner.remove());

    header.appendChild(label);
    header.appendChild(closeBtn);

    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.cssText = 'display:block;color:#60a5fa;font-weight:600;text-decoration:none;word-break:break-all;line-height:1.4;';
    link.textContent = `⬇️ Tap to download ${filename}`;

    banner.appendChild(header);
    banner.appendChild(link);
    document.body.appendChild(banner);

    // Don't let it linger forever if it's never dismissed manually.
    setTimeout(() => banner.remove(), 5 * 60 * 1000);
  }

  showDownloadProgress(message, filename = '') {
    if (!this.downloadProgress) return;
    if (this.downloadProgressText) {
      this.downloadProgressText.textContent = message;
    }
    if (this.downloadProgressFilename) {
      this.downloadProgressFilename.textContent = filename;
      this.downloadProgressFilename.hidden = !filename;
    }
    this.downloadProgress.hidden = false;
  }

  updateDownloadProgress(message, filename = '') {
    if (this.downloadProgressText) {
      this.downloadProgressText.textContent = message;
    }
    if (this.downloadProgressFilename && filename) {
      this.downloadProgressFilename.textContent = filename;
      this.downloadProgressFilename.hidden = false;
    }
  }

  hideDownloadProgress() {
    if (this.downloadProgress) {
      this.downloadProgress.hidden = true;
    }
  }

  serializeForm(form) {
    const result = {};
    if (!form) return result;
    const formData = new FormData(form);
    for (const [key, value] of formData.entries()) {
      if (value === '') continue;
      if (result[key]) {
        if (Array.isArray(result[key])) {
          result[key].push(value);
        } else {
          result[key] = [result[key], value];
        }
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  showToast(message, isError = false) {
    if (!this.toast) return;
    this.toast.textContent = message;
    
    // Remove all toast type classes
    this.toast.classList.remove('success', 'error', 'info');
    
    // Add appropriate class
    if (isError) {
      this.toast.classList.add('error');
    } else if (message.toLowerCase().includes('copied')) {
      this.toast.classList.add('info');
    } else {
      this.toast.classList.add('success');
    }
    
    this.toast.style.removeProperty('background');
    this.toast.hidden = false;
    
    clearTimeout(this.toastTimer);
    const duration = isError ? 6000 : 2500;
    this.toastTimer = setTimeout(() => {
      this.toast.hidden = true;
    }, duration);
  }

  showAuthCodeModal(message) {
    if (!this.authModal) {
      this.toggleAuthCode(true);
      if (this.authCodeMessage) {
        this.authCodeMessage.hidden = false;
        this.authCodeMessage.textContent = message;
      }
      return;
    }

    if (this.authModalMessage) {
      this.authModalMessage.textContent = message || 'Enter the verification code to continue.';
    }
    if (this.authModalInput) {
      this.authModalInput.value = '';
    }
    if (this.authModalError) {
      this.authModalError.hidden = true;
    }
    this.authModal.hidden = false;
    this.authModalInput?.focus();
  }

  hideAuthCodeModal() {
    if (this.authModal) {
      this.authModal.hidden = true;
    }
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const ui = new IPAToolUI();
  ui.init();
});
