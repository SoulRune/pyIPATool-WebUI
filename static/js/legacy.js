(function () {
  // Escape everything from the network before building HTML strings.
  var ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
  function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"'`]/g, function (c) {
      return ESC_MAP[c];
    });
  }

  var loginForm;
  var logoutButton;
  var accountBox;
  var accountsBox;
  var accountsList;
  var addAccountButton;
  var accountsToggle;
  var accountsCurrent;
  var toast;
  var appFinderSection;
  var versionsSection;
  var authModal;
  var authModalForm;
  var authModalMessage;
  var authModalError;
  var authModalInput;
  var authModalCancel;
  var authCodeMessage;
  var searchForm;
  var directLookupForm;
  var searchResults;
  var versionsList;
  var appTitle;
  var appSubtitle;
  var communityFallbackCheckbox;
  var directCommunityFallbackCheckbox;
  var searchTab;
  var directTab;
  var tabButtons;
  var purchaseModal;
  var purchaseModalForm;
  var purchaseModalCancel;
  var purchaseAppId;
  var purchaseBundleId;
  var downloadProgress;
  var downloadProgressText;
  var downloadProgressFilename;
  var pendingCredentials = null;
  var lastSearchCountry = '';
  var lastSearchPlatform = '';
  var lastSearchCommunityFallback = false;
  var lastSearchCatalogFirst = false;
  var lastSearchMergeCatalogs = false;
  var mergeCatalogs = false;
  var currentAppId = null;
  var currentBundleId = null;
  var currentPlatform = '';
  var currentExternalVersionId = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function setElementHidden(element, hidden) {
    if (!element) {
      return;
    }
    if ('hidden' in element) {
      element.hidden = hidden;
    } else {
      element.style.display = hidden ? 'none' : '';
    }
    try {
      // Force inline display/visibility and aria-hidden for older browsers or CSS overrides
      element.style.display = hidden ? 'none' : '';
      element.style.visibility = hidden ? 'hidden' : 'visible';
      if (hidden) {
        element.setAttribute('aria-hidden', 'true');
      } else {
        element.removeAttribute('aria-hidden');
      }
    } catch (e) {
      // ignore any style assignment errors on exotic elements
    }
  }

  function showToast(message, isError) {
    if (!toast) {
      return;
    }
    toast.textContent = message || '';
    // Same colour coding as the modern UI: red errors, blue "copied", green otherwise.
    var kind = isError ? 'error' : (String(message || '').toLowerCase().indexOf('copied') !== -1 ? 'info' : 'success');
    toast.className = 'toast ' + kind;
    setElementHidden(toast, false);
    window.setTimeout(function () {
      setElementHidden(toast, true);
    }, isError ? 6000 : 3000);
  }

  function serializeForm(form) {
    var result = {};
    if (!form || !form.elements) {
      return result;
    }

    for (var i = 0; i < form.elements.length; i += 1) {
      var element = form.elements[i];
      if (!element.name || element.disabled) {
        continue;
      }
      if ((element.type === 'checkbox' || element.type === 'radio') && !element.checked) {
        continue;
      }
      if (element.type === 'checkbox') {
        result[element.name] = element.checked ? 'on' : '';
      } else {
        result[element.name] = element.value;
      }
    }
    return result;
  }

  function parseJson(text) {
    try {
      return JSON.parse(text);
    } catch (e) {
      return null;
    }
  }

  function apiUrl(path) {
    var baseUrl = window.APP_BASE_URL || '';
    if (baseUrl === '/') {
      baseUrl = '';
    } else if (baseUrl && baseUrl.charAt(baseUrl.length - 1) === '/') {
      baseUrl = baseUrl.slice(0, -1);
    }
    if (path.charAt(0) !== '/') {
      path = '/' + path;
    }
    return baseUrl + path;
  }

  function updateAccountBox(account) {
    if (!accountBox) {
      return;
    }
    var nodes = accountBox.querySelectorAll('[data-field]');
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      var field = node.getAttribute('data-field');
      node.textContent = (account && account[field]) || 'N/A';
    }
  }

  function clearAccountFields() {
    if (!accountBox) {
      return;
    }
    var nodes = accountBox.querySelectorAll('[data-field]');
    for (var i = 0; i < nodes.length; i += 1) {
      nodes[i].textContent = 'N/A';
    }
  }

  function setLoggedIn(isLoggedIn) {
    if (loginForm) {
      setElementHidden(loginForm, isLoggedIn);
    }
    if (logoutButton) {
      setElementHidden(logoutButton, !isLoggedIn);
    }
    if (accountBox) {
      setElementHidden(accountBox, !isLoggedIn);
    }
    var accountExtra = byId('account-extra');
    if (accountExtra) {
      setElementHidden(accountExtra, !isLoggedIn); // the sign-in form has its own certificate hint
    }
    if (appFinderSection) {
      setElementHidden(appFinderSection, !isLoggedIn);
    }
    if (versionsSection) {
      setElementHidden(versionsSection, true);
    }
    if (!isLoggedIn) {
      clearAccountFields();
      if (authCodeMessage) {
        setElementHidden(authCodeMessage, true);
      }
      hidePurchaseModal();
      hideDownloadProgress();
    }
    refreshAccounts();
  }

  // -- several saved sign-ins ------------------------------------------------

  function hasClass(el, name) {
    return (' ' + el.className + ' ').indexOf(' ' + name + ' ') !== -1;
  }

  function setAccountsMenuOpen(open) {
    if (!accountsBox) {
      return;
    }
    var cls = (' ' + accountsBox.className + ' ').replace(' open ', ' ');
    accountsBox.className = (open ? cls + 'open' : cls).replace(/^\s+|\s+$/g, '');
    if (accountsToggle) {
      accountsToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
  }

  function refreshAccounts() {
    if (!accountsBox || !accountsList) {
      return;
    }
    sendRequest('GET', apiUrl('/api/accounts'), null, function (response) {
      var accounts = (response.status >= 200 && response.status < 300 && response.body && response.body.accounts) || [];
      var max = (response.body && response.body.max) || 1;
      var active = null;
      var html = [];
      for (var i = 0; i < accounts.length; i += 1) {
        var a = accounts[i];
        var body = '<span class="account-main">' + (a.active ? '\u2713 ' : '') + esc(a.name || a.email) + '</span>' +
          (a.name ? '<span class="account-sub">' + esc(a.email) + '</span>' : '') +
          (a.storeFront ? '<span class="account-sub account-store" title="App Store region of this Apple ID">Storefront ' + esc(a.storeFront) + '</span>' : '');
        if (a.active) {
          active = a;
          html.push('<li><div class="account-row is-active">' + body + '</div></li>');
        } else {
          html.push('<li><button type="button" class="account-forget" data-account-action="forget" data-account-id="' + esc(a.id) +
            '" title="Forget this saved sign-in">\u2715</button>' +
            '<button type="button" class="account-row" data-account-action="switch" data-account-id="' + esc(a.id) +
            '" title="Switch to this Apple ID">' + body + '</button></li>');
        }
      }
      accountsList.innerHTML = html.join('');
      if (accountsCurrent) {
        accountsCurrent.innerHTML = active ? esc(active.name || active.email) : 'Saved accounts (' + accounts.length + ')';
        accountsCurrent.title = active ? active.email : '';
      }
      if (addAccountButton) {
        addAccountButton.disabled = accounts.length >= max;
        addAccountButton.title = accounts.length >= max ? 'Up to ' + max + ' sign-ins - forget one first'
          : 'Keep this sign-in and sign in with another Apple ID';
      }
      var hide = !active && accounts.length === 0;
      setElementHidden(accountsBox, hide);
      if (hide) {
        setAccountsMenuOpen(false);
      }
    });
  }

  function bindPasswordToggles() {
    var buttons = document.querySelectorAll ? document.querySelectorAll('[data-password-toggle]') : [];
    for (var i = 0; i < buttons.length; i += 1) {
      (function (button) {
        var input = button.parentNode && button.parentNode.getElementsByTagName('input')[0];
        if (!input) {
          return;
        }
        button.onclick = function () {
          var show = input.type === 'password';
          try {
            input.type = show ? 'text' : 'password';
          } catch (e) {
            button.style.display = 'none'; // very old browsers can't change it
            return false;
          }
          button.className = show ? 'password-toggle on' : 'password-toggle';
          button.title = show ? 'Hide password' : 'Show password';
          button.setAttribute('aria-pressed', show ? 'true' : 'false');
          return false;
        };
      })(buttons[i]);
    }
  }

  function handleAddAccount() {
    setAccountsMenuOpen(false);
    if (loginForm && loginForm.style.display !== 'none' && !loginForm.hidden) {
      var emailInput = loginForm.elements && loginForm.elements.email;
      if (emailInput && emailInput.focus) {
        emailInput.focus();
      }
      return;
    }
    sendRequest('POST', apiUrl('/api/accounts/add'), {}, function (response) {
      if (response.status < 200 || response.status >= 300) {
        showToast((response.body && response.body.error) || 'Failed', true);
        return;
      }
      showToast('Sign in with another Apple ID - the current one stays saved');
      setLoggedIn(false);
    });
  }

  function handleAccountAction(action, id) {
    if (!id) {
      return;
    }
    if (action === 'forget' && !window.confirm('Forget this saved sign-in? Signing in again needs the password (and maybe a code).')) {
      return;
    }
    if (action === 'switch') {
      setAccountsMenuOpen(false);
    }
    var path = action === 'switch' ? '/api/accounts/switch' : '/api/accounts/forget';
    sendRequest('POST', apiUrl(path), { id: id }, function (response) {
      if (response.status < 200 || response.status >= 300 || !response.body) {
        showToast((response.body && response.body.error) || 'Failed', true);
        return;
      }
      if (action === 'switch' && response.body.account) {
        updateAccountBox(response.body.account);
        setLoggedIn(true);
        showToast('Switched to ' + response.body.account.email);
      } else {
        refreshAccounts();
      }
    });
  }

  function showAuthModal(message) {
    if (!authModal) {
      return;
    }
    if (authModalMessage) {
      authModalMessage.textContent = message || 'Enter the verification code to continue.';
    }
    if (authModalError) {
      authModalError.textContent = '';
      setElementHidden(authModalError, true);
    }
    if (authModalInput) {
      authModalInput.value = '';
      try {
        authModalInput.focus();
      } catch (e) {
        // ignore focus issues on old devices
      }
    }
    setElementHidden(authModal, false);
  }

  function hideAuthModal() {
    setElementHidden(authModal, true);
  }

  function showPurchaseModal(appId, bundleId) {
    if (!purchaseModal) {
      return;
    }
    if (purchaseAppId) {
      purchaseAppId.value = appId || '';
    }
    if (purchaseBundleId) {
      purchaseBundleId.value = bundleId || '';
    }
    setElementHidden(purchaseModal, false);
  }

  function hidePurchaseModal() {
    setElementHidden(purchaseModal, true);
  }

  function showDownloadProgress(message, filename) {
    if (!downloadProgress) {
      return;
    }
    if (downloadProgressText) {
      downloadProgressText.textContent = message || 'Downloading...';
    }
    if (downloadProgressFilename) {
      downloadProgressFilename.textContent = filename || '';
      setElementHidden(downloadProgressFilename, !filename);
    }
    setElementHidden(downloadProgress, false);
  }

  function updateDownloadProgress(message, filename) {
    if (downloadProgressText) {
      downloadProgressText.textContent = message || 'Downloading...';
    }
    if (downloadProgressFilename) {
      downloadProgressFilename.textContent = filename || '';
      setElementHidden(downloadProgressFilename, !filename);
    }
  }

  function hideDownloadProgress() {
    setElementHidden(downloadProgress, true);
  }

  function copyTextToClipboard(text) {
    if (!text) {
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        showToast('Copied: ' + text);
      }, function () {
        showToast('Failed to copy', true);
      });
      return;
    }

    var textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.setAttribute('readonly', '');
    textArea.style.position = 'fixed';
    textArea.style.left = '-9999px';
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand('copy');
      showToast('Copied: ' + text);
    } catch (e) {
      showToast('Failed to copy', true);
    } finally {
      document.body.removeChild(textArea);
    }
  }

  function sendRequest(method, url, payload, callback) {
    var xhr = new XMLHttpRequest();
    if (!xhr) {
      callback({ status: 0, body: null });
      return;
    }

    xhr.open(method, url, true);
    if (payload !== null) {
      xhr.setRequestHeader('Content-Type', 'application/json');
    }
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) {
        return;
      }
      var body = null;
      try {
        body = parseJson(xhr.responseText);
      } catch (e) {
        body = null;
      }
      callback({ status: xhr.status, body: body });
    };
    if (payload === null) {
      xhr.send(null);
    } else {
      xhr.send(JSON.stringify(payload));
    }
  }

  function handleLoginFormSubmit(event) {
    if (event && event.preventDefault) {
      event.preventDefault();
    }
    if (!loginForm) {
      return false;
    }

    var entries = serializeForm(loginForm);
    pendingCredentials = {
      email: entries.email || '',
      password: entries.password || ''
    };
    performLogin(pendingCredentials);
    return false;
  }

  var CODE_REJECTED_MESSAGE = "Apple didn't accept the sign-in. The code may be wrong or expired - or the password is wrong (Apple reports both the same way). Check the password and request a new code.";

  function setLoginBusy(busy) {
    var buttons = [];
    if (loginForm) {
      buttons.push(loginForm.querySelector('button[type="submit"]'));
    }
    if (authModalForm) {
      buttons.push(authModalForm.querySelector('button[type="submit"]'));
    }
    for (var i = 0; i < buttons.length; i += 1) {
      var button = buttons[i];
      if (!button) {
        continue;
      }
      if (busy) {
        if (!button.getAttribute('data-label')) {
          button.setAttribute('data-label', button.textContent || button.innerText || '');
        }
        button.textContent = 'Signing in\u2026 (can take up to a minute)';
        button.disabled = true;
      } else {
        if (button.getAttribute('data-label')) {
          button.textContent = button.getAttribute('data-label');
        }
        button.disabled = false;
      }
    }
  }

  // Stays visible under the form until the next attempt (a sign-in can
  // take up to a minute; a toast is easy to miss).
  function setLoginError(message) {
    var box = byId('login-error');
    if (!box) {
      return;
    }
    box.textContent = message || '';
    setElementHidden(box, !message);
  }

  function showAuthModalError(message) {
    if (authModalError) {
      authModalError.textContent = message;
      setElementHidden(authModalError, false);
    }
  }

  function performLogin(credentials) {
    var payload = {
      email: credentials.email || '',
      password: credentials.password || ''
    };
    var baseCredentials = {
      email: credentials.email || '',
      password: credentials.password || ''
    };

    if (credentials.authCode) {
      payload.authCode = String(credentials.authCode).replace(/\s+/g, '');
    }

    setLoginBusy(true);
    setLoginError('');
    sendRequest('POST', apiUrl('/api/auth/login'), payload, function (response) {
      setLoginBusy(false);
      var result = response.body || {};

      if (response.status === 401 && result.authCodeRequired) {
        pendingCredentials = baseCredentials;
        if (credentials.authCode) {
          // A code was sent and Apple asks again: it didn't accept it.
          showAuthModal(result.error || 'Verification code required');
          showAuthModalError(CODE_REJECTED_MESSAGE);
          showToast(CODE_REJECTED_MESSAGE, true);
          return;
        }
        showAuthModal(result.error || 'Verification code required');
        return;
      }

      if (response.status >= 200 && response.status < 300 && result.account) {
        pendingCredentials = null;
        hideAuthModal();
        if (loginForm) {
          loginForm.reset();
        }
        updateAccountBox(result.account);
        setLoggedIn(true);
        showToast('Signed in successfully');
        return;
      }

      var message = (result && result.error) ? result.error : 'Login failed';
      if (credentials.authCode) {
        pendingCredentials = baseCredentials;
        // The modal was closed when the code was submitted: reopen it with the error.
        showAuthModal('Enter the verification code to continue.');
        showAuthModalError(message);
      } else {
        pendingCredentials = null;
        setLoginError(message);
      }
      showToast(message, true);
    });
  }

  function handleAuthModalSubmit(event) {
    if (event && event.preventDefault) {
      event.preventDefault();
    }

    if (!pendingCredentials) {
      showToast('Please start the sign-in flow again', true);
      hideAuthModal();
      return false;
    }

    var code = authModalInput && authModalInput.value ? authModalInput.value.trim() : '';
    if (!code) {
      if (authModalError) {
        authModalError.textContent = 'Enter the verification code to continue.';
        setElementHidden(authModalError, false);
      }
      return false;
    }

    pendingCredentials.authCode = code;
    hideAuthModal();
    performLogin(pendingCredentials);
    return false;
  }

  function handleLogout() {
    sendRequest('POST', apiUrl('/api/auth/logout'), {}, function () {
      showToast('Signed out');
      setLoggedIn(false);
    });
  }

  function refreshAccountState() {
    sendRequest('GET', apiUrl('/api/account'), null, function (response) {
      if (response.status >= 200 && response.status < 300 && response.body && response.body.account) {
        updateAccountBox(response.body.account);
        setLoggedIn(true);
        return;
      }
      setLoggedIn(false);
    });
  }

  function switchTab(tabName) {
    // Only touch buttons that declare a data-tab attribute, so as not to wipe
    // unrelated button classes (e.g. .secondary). Use querySelectorAll when
    // available; otherwise fall back to filtering the global button list.
    var tabs = null;
    if (document.querySelectorAll) {
      tabs = document.querySelectorAll('button[data-tab]');
    } else if (tabButtons) {
      var tmp = [];
      for (var k = 0; k < tabButtons.length; k += 1) {
        try {
          if (tabButtons[k] && tabButtons[k].getAttribute && tabButtons[k].getAttribute('data-tab')) {
            tmp.push(tabButtons[k]);
          }
        } catch (err) {}
      }
      tabs = tmp;
    }
    if (!tabs) {
      return;
    }

    for (var i = 0; i < tabs.length; i += 1) {
      var button = tabs[i];
      var isActive = button.getAttribute && (button.getAttribute('data-tab') === tabName);
      try {
        if (button.classList) {
          if (isActive) button.classList.add('active'); else button.classList.remove('active');
        } else {
          // preserve existing classes while toggling 'active'
          var cls = (button.className || '').split(/\s+/).filter(function (c) { return c && c !== 'active'; });
          if (isActive) cls.push('active');
          button.className = cls.join(' ');
        }
      } catch (err) {
        // ignore class toggling errors
      }
    }

    if (searchTab && directTab) {
      if (tabName === 'direct') {
        setElementHidden(searchTab, true);
        setElementHidden(directTab, false);
        // Ensure CSS active class matches for older browsers
        try { searchTab.className = 'tab-content'; } catch (e) {}
        try { directTab.className = 'tab-content active'; } catch (e) {}
      } else {
        setElementHidden(searchTab, false);
        setElementHidden(directTab, true);
        try { searchTab.className = 'tab-content active'; } catch (e) {}
        try { directTab.className = 'tab-content'; } catch (e) {}
      }
    }

    if (versionsSection) {
      setElementHidden(versionsSection, true);
    }
    if (searchResults) {
      setElementHidden(searchResults, true);
    }
  }

  function renderSearchResults(results) {
    if (!searchResults) {
      return;
    }

    if (!results || results.length === 0) {
      searchResults.innerHTML = '<div class="empty-state"><p>No apps found</p></div>';
      setElementHidden(searchResults, false);
      return;
    }

    var html = [];
    for (var i = 0; i < results.length; i += 1) {
      var app = results[i];
      // Same structure/classes as the modern UI's cards (app-card-title,
      // app-card-meta, badge), so both stylesheets render them alike.
      var priceHtml = app && app.price && app.price > 0
        ? '<span>\uD83D\uDCB0 $' + esc(app.price) + '</span>'
        : '<span class="badge">Free</span>';
      html.push('<div class="app-card" data-app-id="' + esc(app.trackId || '') + '" data-bundle-id="' + esc(app.bundleId || '') + '">' +
        '<h3 class="app-card-title">' + esc(app.trackName || 'Unknown') + '</h3>' +
        '<div class="app-card-meta"><span>\uD83D\uDCE6 ' + esc(app.bundleId || 'N/A') + '</span><span>\uD83C\uDFF7\uFE0F v' + esc(app.version || 'N/A') + '</span>' + priceHtml + '</div>' +
        '<div class="app-card-id"><span class="copy-code" data-copy="' + esc(app.trackId || '') + '" title="Click to copy App ID"><span class="copy-icon">\uD83C\uDD94</span> <span>' + esc(app.trackId || '') + '</span></span>' +
        (/^\d+$/.test(String(app.trackId || '')) ? ' <a class="appstore-chip" href="https://itunes.apple.com/' + (lastSearchCountry ? esc(lastSearchCountry) + '/' : '') + 'app/id' + esc(app.trackId) + '" target="_blank" rel="noopener noreferrer" title="Open in App Store">\uD83D\uDECD\uFE0F App Store</a>' : '') +
        '</div>' +
        '</div>');
    }
    searchResults.innerHTML = html.join('');

    var cards = searchResults.getElementsByTagName('div');
    for (var j = 0; j < cards.length; j += 1) {
      var card = cards[j];
      var className = card.className || '';
      if ((' ' + className + ' ').indexOf(' app-card ') === -1) {
        continue;
      }
      card.onclick = function (event) {
        var clicked = event && (event.target || event.srcElement);
        if (clicked && findAncestorByClass(clicked, 'appstore-chip')) {
          return true; // let the link open the App Store
        }
        if (clicked && (findAncestorByClass(clicked, 'copy-code') || (clicked.className && String(clicked.className).indexOf('copy-code') !== -1))) {
          return false;
        }
        var appId = this.getAttribute('data-app-id');
        var bundleId = this.getAttribute('data-bundle-id');
        mergeCatalogs = lastSearchMergeCatalogs;
        loadAppVersions(appId, bundleId, null, lastSearchPlatform, lastSearchCommunityFallback, lastSearchCatalogFirst);
        return false;
      };
    }

    setElementHidden(searchResults, false);
  }

  function runSearch() {
    if (!searchForm) {
      return;
    }

    var formData = serializeForm(searchForm);
    if (!formData.term) {
      showToast('Please enter a search term', true);
      return;
    }

    var params = [];
    params.push('term=' + encodeURIComponent(formData.term));
    if (formData.limit) {
      params.push('limit=' + encodeURIComponent(formData.limit));
    }
    lastSearchPlatform = formData.platform || '';
    if (lastSearchPlatform) {
      params.push('platform=' + encodeURIComponent(lastSearchPlatform));
    }
    lastSearchCountry = (formData.country || '').toLowerCase();
    if (lastSearchCountry) {
      params.push('country=' + encodeURIComponent(lastSearchCountry.toUpperCase()));
    }
    lastSearchCommunityFallback = formData.communityFallback === 'on';
    lastSearchCatalogFirst = formData.catalogFirst === 'on';
    lastSearchMergeCatalogs = formData.mergeCatalogs === 'on';

    showToast('Searching...');
    sendRequest('GET', apiUrl('/api/search') + '?' + params.join('&'), null, function (response) {
      if (response.status < 200 || response.status >= 300 || !response.body) {
        showToast('Search failed', true);
        return;
      }
      renderSearchResults(response.body.results || []);
    });
  }

  function loadAppVersions(appId, bundleId, externalVersionId, platform, communityFallback, catalogFirst) {
    if (catalogFirst && !externalVersionId) {
      // "Private catalog first": the catalog's versions when it has this app,
      // otherwise Apple as usual.
      loadAppVersionsFromCatalog(appId, bundleId, platform, communityFallback, function (shown) {
        if (!shown) {
          loadAppVersions(appId, bundleId, externalVersionId, platform, communityFallback, false);
        }
      });
      return;
    }
    currentAppId = appId || null;
    currentBundleId = bundleId || null;
    currentExternalVersionId = externalVersionId || null;
    currentPlatform = platform || '';

    if (!versionsSection || !versionsList) {
      return;
    }

    var communityFallbackEnabled = !!communityFallback;

    if (appTitle) {
      appTitle.textContent = 'Loading...';
    }
    if (appSubtitle) {
      appSubtitle.textContent = '';
    }
    versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div><div class="hint" style="margin-top:1rem;">Loading versions...</div></div>';
    setElementHidden(versionsSection, false);

    var params = [];
    if (currentAppId) {
      params.push('appId=' + encodeURIComponent(currentAppId));
    }
    if (currentBundleId) {
      params.push('bundleId=' + encodeURIComponent(currentBundleId));
    }
    if (currentExternalVersionId) {
      params.push('externalVersionId=' + encodeURIComponent(currentExternalVersionId));
    }
    if (currentPlatform) {
      params.push('platform=' + encodeURIComponent(currentPlatform));
    }

    var url = apiUrl('/api/versions');
    if (params.length > 0) {
      url += '?' + params.join('&');
    }

    sendRequest('GET', url, null, function (response) {
      if (response.status >= 400 || !response.body) {
        var body = response.body || {};
        var errorText = body.error || 'Unable to load versions';
        var metadata = body.metadata || {};

        // Apple Arcade: not supported - show what the community database
        // knows, read-only (version ids only), regardless of the toggle.
        if (body.arcade) {
          loadAppVersionsFromCommunity(currentAppId, currentBundleId, body.error || '', body.arcadeLatestVersionId || '');
          return;
        }

        // No license: always the license flow, never the community fallback.
        var isLicenseError = body.licenseRequired || (body.error && body.error.toLowerCase().indexOf('license') !== -1) || metadata.failureType === '9610';
        if (isLicenseError) {
          if (purchaseModal) {
            showPurchaseModal(currentAppId, currentBundleId);
            versionsList.innerHTML = '<div class="empty-state"><p>A license is required to view versions for this app.</p></div>';
          } else if (window.confirm('A license is required to view versions for this app. Would you like to acquire it now?')) {
            acquireLicenseAndRetry(currentAppId, currentBundleId, currentExternalVersionId, currentPlatform);
          } else {
            versionsList.innerHTML = '<div class="empty-state"><p>License required</p></div>';
          }
          return;
        }

        // Apple's generic refusal (5002, m-allowed false): only then try Timbrd.
        if (communityFallbackEnabled && metadata.failureType === '5002' && metadata['m-allowed'] === false) {
          showToast('Apple refused this app (not a licensing issue) - trying the community database instead...');
          loadAppVersionsFromCommunity(currentAppId, currentBundleId);
          return;
        }

        showToast(errorText, true);
        versionsList.innerHTML = '<div class="empty-state"><p>' + esc(errorText) + '</p></div>';
        return;
      }

      if (response.body.arcadeProbeVersionId) {
        showToast('Apple Arcade: Apple answered the version list only when asked for version ' + response.body.arcadeProbeVersionId + ' - some versions may still refuse to download');
      }
      var identifiers = response.body.externalVersionIdentifiers || [];
      var latest = response.body.latestExternalVersionId || '';
      if (!identifiers.length) {
        versionsList.innerHTML = '<div class="empty-state"><p>No versions found</p></div>';
        return;
      }

      // Apply client-side external version filter if provided (backend may ignore it)
      if (currentExternalVersionId) {
        var filtered = [];
        for (var k = 0; k < identifiers.length; k += 1) {
          if (String(identifiers[k]) === String(currentExternalVersionId)) {
            filtered.push(identifiers[k]);
          }
        }
        identifiers = filtered;
        if (!identifiers.length) {
          versionsList.innerHTML = '<div class="empty-state"><p>No versions match the provided Version ID</p></div>';
          return;
        }
      }

      if (mergeCatalogs && !currentExternalVersionId) {
        fetchCatalogEntries(function (entries) {
          loadAndRenderVersionMetadata(mergeVersionIds(identifiers, entries), latest, entries);
        });
        return;
      }
      loadAndRenderVersionMetadata(identifiers, latest, []);
    });
  }

  // "Merge version catalogs": the catalogs' entries (private catalog first,
  // then Timbrd, bilin); [] if none answer.
  function fetchCatalogEntries(callback) {
    var params = [];
    if (currentAppId) {
      params.push('appId=' + encodeURIComponent(currentAppId));
    }
    if (currentBundleId) {
      params.push('bundleId=' + encodeURIComponent(currentBundleId));
    }
    sendRequest('GET', apiUrl('/api/versions/community') + '?' + params.join('&'), null, function (response) {
      var entries = (response.status >= 200 && response.status < 300 && response.body && response.body.entries) || [];
      callback(entries);
    });
  }

  // Apple's ids plus the ids only the catalogs know, in Apple's order.
  function mergeVersionIds(identifiers, entries) {
    var seen = {};
    var all = [];
    var i;
    for (i = 0; i < identifiers.length; i += 1) {
      if (!seen[String(identifiers[i])]) {
        seen[String(identifiers[i])] = true;
        all.push(String(identifiers[i]));
      }
    }
    for (i = 0; i < entries.length; i += 1) {
      var id = String(entries[i].externalVersionId || '');
      if (/^\d+$/.test(id) && !seen[id]) {
        seen[id] = true;
        all.push(id);
      }
    }
    var ascending = identifiers.length < 2 || Number(identifiers[0]) <= Number(identifiers[identifiers.length - 1]);
    all.sort(function (a, b) { return ascending ? Number(a) - Number(b) : Number(b) - Number(a); });
    return all;
  }

  function annotateWithCatalogs(catalogById) {
    var cards = versionsList.getElementsByClassName ? versionsList.getElementsByClassName('version-card') : [];
    for (var i = 0; i < cards.length; i += 1) {
      var entry = catalogById[cards[i].getAttribute('data-version-id')];
      var lists = cards[i].getElementsByTagName('dl');
      if (!entry || !lists.length) {
        continue;
      }
      var sources = [entry.source].concat(entry.alsoIn || []).join(', ');
      lists[0].insertAdjacentHTML('beforeend', '<dt>Catalogs:</dt><dd>' + esc(sources) +
        (entry.status ? ' (' + esc(entry.status) + ' in ' + esc(entry.source) + ')' : '') + '</dd>');
    }
  }

  function loadAndRenderVersionMetadata(identifiers, latest, catalogEntries) {
    var versionCount = identifiers.length;
    var catalogById = {};
    for (var c = 0; c < (catalogEntries || []).length; c += 1) {
      catalogById[String(catalogEntries[c].externalVersionId)] = catalogEntries[c];
    }
    var loaded = 0;
    // Index-keyed slots keep the original order whatever XHR finishes first.
    var versionSlots = new Array(versionCount);

    function finish() {
      if (loaded < versionCount) {
        return;
      }

      var versions = [];
      var fromCatalogs = [];
      for (var i = 0; i < versionSlots.length; i += 1) {
        if (versionSlots[i]) {
          versions.push(versionSlots[i]);
        } else if (catalogById[String(identifiers[i])]) {
          // Apple didn't describe it, but a catalog knows it: keep it.
          var known = catalogById[String(identifiers[i])];
          var copy = {};
          for (var key in known) {
            if (Object.prototype.hasOwnProperty.call(known, key)) {
              copy[key] = known[key];
            }
          }
          copy.appleRefused = true;
          fromCatalogs.push(copy);
        }
      }

      if (versions.length === 0 && fromCatalogs.length === 0) {
        versionsList.innerHTML = '<div class="empty-state"><p>No versions found</p></div>';
        return;
      }

      var first = versions[0] || {};
      if (appTitle) {
        appTitle.textContent = first.itemName || 'App Versions';
      }
      if (appSubtitle) {
        var skipped = versionCount - versions.length - fromCatalogs.length;
        appSubtitle.textContent = (first.bundleId || currentBundleId || currentAppId || 'Versions') + ' | ' + versions.length + ' version' + (versions.length === 1 ? '' : 's') +
          (fromCatalogs.length ? ' | ' + fromCatalogs.length + ' more from catalogs' : '') +
          (skipped > 0 ? ' | ' + skipped + ' not served by Apple (hidden)' : '');
      }

      if (versions.length) {
        renderVersionCards(versions, latest);
        annotateWithCatalogs(catalogById);
      } else {
        versionsList.innerHTML = '';
      }
      if (fromCatalogs.length) {
        versionsList.insertAdjacentHTML('beforeend', '<div class="catalog-extra"><h4 class="catalog-extra-title">Not described by Apple - from version catalogs</h4>' +
          communityVersionsHtml(fromCatalogs, false) + '</div>');
      }
    }

    function fetchMetadataForVersion(versionId, index) {
      var params = [];
      if (currentAppId) {
        params.push('appId=' + encodeURIComponent(currentAppId));
      }
      if (currentBundleId) {
        params.push('bundleId=' + encodeURIComponent(currentBundleId));
      }
      params.push('versionId=' + encodeURIComponent(versionId));

      var metadataUrl = apiUrl('/api/version-metadata') + '?' + params.join('&');
      sendRequest('GET', metadataUrl, null, function (response) {
        loaded += 1;
        // Show progress: apps with a long history need many requests to
        // Apple and the list only renders once all of them are back.
        var hints = versionsList.getElementsByClassName ? versionsList.getElementsByClassName('hint') : [];
        if (hints.length && loaded < versionCount) {
          hints[0].textContent = 'Loading version details... ' + loaded + ' / ' + versionCount;
        }
        if (response.status >= 200 && response.status < 300 && response.body) {
          var metadata = response.body;
          if (!metadata.versionId) {
            metadata.versionId = versionId;
          }
          versionSlots[index] = metadata;
        }
        inFlight -= 1;
        finish();
        pump();
      });
    }

    // At most 4 metadata requests at once (old devices choke on hundreds).
    var nextIndex = 0;
    var inFlight = 0;
    var MAX_IN_FLIGHT = 4;
    function pump() {
      while (inFlight < MAX_IN_FLIGHT && nextIndex < identifiers.length) {
        inFlight += 1;
        fetchMetadataForVersion(identifiers[nextIndex], nextIndex);
        nextIndex += 1;
      }
    }
    pump();
  }

  function formatLegacyReleaseDisplay(display, raw) {
    // Parse ISO dates by hand and use Date.UTC(): iOS 6 WebKit returns
    // Invalid Date for ISO strings without a time zone.
    function parseDate(value) {
      if (!value) {
        return null;
      }
      var m = String(value).match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2}))?/);
      if (!m) {
        return null;
      }
      var year = parseInt(m[1], 10);
      var month = parseInt(m[2], 10) - 1;
      var day = parseInt(m[3], 10);
      var hour = m[4] ? parseInt(m[4], 10) : 0;
      var minute = m[5] ? parseInt(m[5], 10) : 0;
      var second = m[6] ? parseInt(m[6], 10) : 0;
      var utcMillis = Date.UTC(year, month, day, hour, minute, second);
      if (isNaN(utcMillis)) {
        return null;
      }
      return new Date(utcMillis);
    }

    if (display) {
      var m = display.match(/\((\d{4}-\d{2}-\d{2})\)$/);
      if (m && m[1]) {
        var d = parseDate(m[1]);
        if (d) {
          return display.replace(m[1], d.toLocaleDateString());
        }
      }
      if (/^\d{4}-\d{2}-\d{2}/.test(display)) {
        var d2 = parseDate(display);
        return d2 ? d2.toLocaleDateString() : display;
      }
      return display;
    }
    if (raw) {
      var dr = parseDate(raw);
      return dr ? dr.toLocaleDateString() : 'Unknown';
    }
    return 'Unknown';
  }

  function renderVersionCards(versions, latest) {
    var html = [];
    for (var i = 0; i < versions.length; i += 1) {
      var version = versions[i];
      var versionId = version.versionId || '';
      var releaseDate = formatLegacyReleaseDisplay(version.releaseDateDisplay, version.releaseDate);
      var fileSizeMB = 'Unknown';
      if (version.fileSize) {
        fileSizeMB = (version.fileSize / (1024 * 1024)).toFixed(2) + ' MB';
      }
      var isLatest = latest && versionId === latest;
      html.push('<div class="version-card' + (isLatest ? ' latest' : '') + '" data-version-id="' + esc(versionId) + '"><div class="version-header"><div class="version-basic"><div><strong>Version:</strong> ' + esc(version.displayVersion || 'N/A') + '</div><div><strong>Build:</strong> ' + esc(version.buildNumber || 'N/A') + '</div><div><strong>Size:</strong> ' + esc(fileSizeMB) + '</div><div><strong>Released:</strong> ' + esc(releaseDate) + '</div>' + (version.minimumOsVersion ? '<div title="Minimum OS version, from this version\'s Info.plist"><strong>Requires:</strong> ' + esc(version.minimumOsName || 'iOS') + ' ' + esc(version.minimumOsVersion) + '+</div>' : '') + '</div><span class="expand-icon">▼</span></div><div class="version-details"><dl><dt>Version ID:</dt><dd><span class="copy-code" data-copy="' + esc(versionId) + '" title="Click to copy Version ID">' + esc(versionId || 'N/A') + '</span></dd><dt>Bundle ID:</dt><dd>' + esc(version.bundleId || 'N/A') + '</dd><dt>Developer:</dt><dd>' + esc(version.artistName || 'N/A') + '</dd><dt>Genre:</dt><dd>' + esc(version.genre || 'N/A') + '</dd><dt>Age Rating:</dt><dd>' + esc(version.ageRating || 'N/A') + '</dd><dt>Copyright:</dt><dd>' + esc(version.copyright || 'N/A') + '</dd></dl><div class="version-actions"><button type="button" class="download-version-btn" data-version-id="' + esc(versionId) + '">Download IPA</button> <button type="button" class="save-server-btn secondary" data-version-id="' + esc(versionId) + '" title="Save directly on the machine running the server, skip the browser download entirely">💾 Save on server</button> <button type="button" class="install-ota-btn secondary" data-version-id="' + esc(versionId) + '" title="Install straight onto this iPhone/iPad over the network">\uD83D\uDCF2 Install on device</button></div></div></div>');
    }
    versionsList.innerHTML = html.join('');
  }

  function toggleLegacyVersionCard(card) {
    if (!card) {
      return;
    }
    if (card.className.indexOf('expanded') === -1) {
      card.className = card.className + ' expanded';
    } else {
      card.className = card.className.replace(' expanded', '');
    }
  }

  function loadAppVersionsFromCatalog(appId, bundleId, platform, communityFallback, done) {
    var params = [];
    if (appId) {
      params.push('appId=' + encodeURIComponent(appId));
    }
    if (bundleId) {
      params.push('bundleId=' + encodeURIComponent(bundleId));
    }
    currentAppId = appId || null;
    currentBundleId = bundleId || null;
    currentExternalVersionId = null;
    currentPlatform = platform || '';
    if (appTitle) {
      appTitle.textContent = 'Loading...';
    }
    if (appSubtitle) {
      appSubtitle.textContent = '';
    }
    versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div><div class="hint" style="margin-top:1rem;">Reading the private catalog...</div></div>';
    setElementHidden(versionsSection, false);
    sendRequest('GET', apiUrl('/api/versions/catalog') + '?' + params.join('&'), null, function (response) {
      var body = response.body || {};
      var entries = body.entries || [];
      if (response.status < 200 || response.status >= 300) {
        showToast('Private catalog: ' + (body.error || 'unavailable') + ' - asking Apple', true);
        done(false);
        return;
      }
      if (!body.found || !entries.length) {
        showToast('Not in the private catalog - asking Apple');
        done(false);
        return;
      }
      if (!currentBundleId && body.bundleId) {
        currentBundleId = body.bundleId;
      }
      if (appTitle) {
        appTitle.textContent = 'App Versions';
      }
      if (appSubtitle) {
        appSubtitle.textContent = 'Private catalog \u2022 ' + entries.length + ' version' + (entries.length === 1 ? '' : 's');
      }
      var updated = body.updatedAt ? ' (updated ' + esc(String(body.updatedAt).slice(0, 10)) + ')' : '';
      versionsList.innerHTML = '<div class="notice-info">\uD83D\uDCDA From the private catalog' + updated +
        ' - Apple wasn\'t asked, so versions released since then aren\'t here. ' +
        '<button type="button" class="secondary small" id="ask-apple-button">Ask Apple</button></div>' +
        communityVersionsHtml(entries, false);
      var ask = byId('ask-apple-button');
      if (ask) {
        ask.onclick = function () {
          loadAppVersions(appId, bundleId, null, platform, communityFallback, false);
          return false;
        };
      }
      done(true);
    });
  }

  function loadAppVersionsFromCommunity(appId, bundleId, arcadeNotice, currentVersionId) {
    var params = [];
    if (appId) {
      params.push('appId=' + encodeURIComponent(appId));
    }
    if (bundleId) {
      params.push('bundleId=' + encodeURIComponent(bundleId));
    }

    if (appTitle) {
      appTitle.textContent = 'Loading...';
    }
    if (appSubtitle) {
      appSubtitle.textContent = '';
    }
    versionsList.innerHTML = '<div style="text-align:center;padding:2rem;"><div class="loading"></div><div class="hint" style="margin-top:1rem;">Loading community versions...</div></div>';
    setElementHidden(versionsSection, false);

    var url = apiUrl('/api/versions/community');
    if (params.length > 0) {
      url += '?' + params.join('&');
    }

    sendRequest('GET', url, null, function (response) {
      var entries = [];
      var communityError = '';
      var communitySource = '';
      if (response.status >= 400 || !response.body) {
        var body = response.body || {};
        var errorText = body.error || 'Failed to load community versions';
        if (!currentVersionId) {
          showToast(errorText, true);
          versionsList.innerHTML = '<div class="empty-state"><p>' + esc(errorText) + '</p></div>';
          return;
        }
        communityError = errorText;
      } else {
        entries = response.body.entries || [];
        communitySource = response.body.source || '';
      }

      // Apple Arcade: the current version is the one Apple serves - first,
      // with download buttons; the rest stays read-only.
      if (currentVersionId) {
        var current = null;
        var rest = [];
        for (var i = 0; i < entries.length; i += 1) {
          if (!current && String(entries[i].externalVersionId) === String(currentVersionId)) {
            current = entries[i];
          } else {
            rest.push(entries[i]);
          }
        }
        var top = { externalVersionId: currentVersionId, bundleVersion: 'current', current: true };
        if (current) {
          top.bundleVersion = current.bundleVersion || 'current';
          top.size = current.size;
          top.createdAt = current.createdAt;
        }
        rest.unshift(top);
        entries = rest;
      }

      if (appTitle) {
        appTitle.textContent = 'App Versions';
      }
      if (appSubtitle) {
        appSubtitle.textContent = 'Community catalogs (' + (communitySource || 'timbrd') + ') \u2022 ' + entries.length + ' version' + (entries.length === 1 ? '' : 's');
      }
      renderCommunityVersions(entries, false);
      if (arcadeNotice) {
        var title = '\uD83D\uDD79\uFE0F Apple Arcade.';
        var extra = communityError ? ' (Community database: ' + communityError + ')' : '';
        versionsList.innerHTML = '<div class="notice-warning"><strong>' + title + '</strong> ' +
          esc(arcadeNotice + extra) + '</div>' + versionsList.innerHTML;
      }
    });
  }

  function renderCommunityVersions(entries, readOnly) {
    if (!entries || entries.length === 0) {
      versionsList.innerHTML = '<div class="empty-state"><p>No versions found in the community database</p></div>';
      return;
    }
    versionsList.innerHTML = communityVersionsHtml(entries, readOnly);
  }

  function communityVersionsHtml(entries, readOnly) {

    var bundleIdText = currentBundleId || 'N/A';
    var html = [];
    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      var sizeText = entry.size ? (entry.size / (1024 * 1024)).toFixed(2) + ' MB' : 'Unknown';
      var fromCatalog = String(entry.source || '').indexOf('catalog') === 0;
      var dateText = entry.createdAt ? (fromCatalog ? String(entry.createdAt).slice(0, 10) : entry.createdAt)
        : (entry.releaseDateDisplay || 'Unknown');
      var catalogDetails = '';
      var detailPairs = [['Developer', entry.artist], ['Genre', entry.genre], ['Age Rating', entry.ageRating], ['Copyright', entry.copyright]];
      for (var d = 0; d < detailPairs.length; d += 1) {
        if (detailPairs[d][1]) {
          catalogDetails += '<dt>' + detailPairs[d][0] + ':</dt><dd>' + esc(detailPairs[d][1]) + '</dd>';
        }
      }
      var vid = entry.externalVersionId || '';
      html.push('<div class="version-card" data-version-id="' + esc(vid) + '"><div class="version-header"><div class="version-basic"><div><strong>Version:</strong> ' + esc(entry.bundleVersion || 'unknown') + (entry.current ? ' <span class="badge-current">current version</span>' : '') + (entry.appleRefused ? ' <span class="badge-unknown" title="Apple didn\'t describe this version for this account - it may still download">not described by Apple</span>' : '') + (entry.status === 'lost' ? ' <span class="badge-lost">lost</span>' : (entry.status === 'unknown' ? ' <span class="badge-unknown">unknown</span>' : '')) + '</div><div><strong>Build:</strong> ' + esc(entry.build || 'N/A') + '</div><div><strong>Size:</strong> ' + esc(sizeText) + '</div><div><strong>' + (fromCatalog ? 'Released' : 'Seen') + ':</strong> ' + esc(dateText) + '</div>' + (entry.minimumOs ? '<div><strong>Requires:</strong> iOS ' + esc(entry.minimumOs) + '+</div>' : '') + '</div><span class="expand-icon">\u25BC</span></div><div class="version-details"><dl><dt>Version ID:</dt><dd><span class="copy-code" data-copy="' + esc(vid) + '" title="Click to copy Version ID">' + esc(vid) + '</span></dd><dt>Bundle ID:</dt><dd>' + esc(bundleIdText) + '</dd>' + catalogDetails + (entry.status === 'lost' ? '<dt>Catalog:</dt><dd>Apple refused this version to the catalog\'s account' + (entry.checkedAt ? ' (checked ' + esc(String(entry.checkedAt).slice(0, 10)) + ')' : '') + ' - Apple\'s answer can change, so it may still download.</dd>' : '') + (entry.alsoIn && entry.alsoIn.length ? '<dt>Also listed in:</dt><dd>' + esc(entry.alsoIn.join(', ')) + '</dd>' : '') + '<dt>Source:</dt><dd>' + (entry.current ? 'Apple (current version)' : (entry.source === 'catalog' ? 'Private catalog' : entry.source === 'catalog-external' ? 'External catalog' : 'Community catalog (' + esc(entry.source || 'timbrd') + ') - not run or endorsed by Apple')) + '</dd></dl>' + (readOnly && !entry.current ? '' : '<div class="version-actions"><button type="button" class="download-version-btn" data-version-id="' + esc(vid) + '">Download IPA</button> <button type="button" class="save-server-btn secondary" data-version-id="' + esc(vid) + '" title="Save directly on the machine running the server, skip the browser download entirely">\uD83D\uDCBE Save on server</button> <button type="button" class="install-ota-btn secondary" data-version-id="' + esc(vid) + '" title="Install straight onto this iPhone/iPad over the network">\uD83D\uDCF2 Install on device</button></div>') + '</div></div>');
    }
    return html.join('');
  }

  function copyLegacyText(text) {
    copyTextToClipboard(text);
  }

  function downloadLegacyVersion(button) {
    if (!button) {
      return;
    }
    var versionId = button.getAttribute('data-version-id');
    if (versionId) {
      downloadVersion(versionId, false);
    }
  }

  function acquireLicenseAndRetry(appId, bundleId, externalVersionId, platform) {
    var payload = {};
    if (appId) {
      payload.appId = appId;
    }
    if (bundleId) {
      payload.bundleId = bundleId;
    }

    showToast('Acquiring license...');
    sendRequest('POST', apiUrl('/api/purchase'), payload, function (response) {
      if (response.status >= 200 && response.status < 300) {
        showToast('License acquired successfully');
        loadAppVersions(appId, bundleId, externalVersionId, platform);
        return;
      }
      var errorMessage = 'Failed to acquire license';
      if (response.body && response.body.error) {
        errorMessage = response.body.error;
      }
      showToast(errorMessage, true);
    });
  }

  // A background job on the server: poll its progress with plain XHR, then
  // download the file through a hidden iframe (iOS 6 has no XHR2 blobs).
  var DOWNLOAD_POLL_INTERVAL_MS = 1500;

  function formatBytes(n) {
    if (!n && n !== 0) {
      return '';
    }
    var mb = n / (1024 * 1024);
    return mb >= 1 ? mb.toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB';
  }

  function fetchFileViaHiddenIframe(url) {
    var iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = url;
    document.body.appendChild(iframe);
    // Leave it in the DOM for a while in case the browser needs it to finish
    // streaming the response; then quietly remove it.
    setTimeout(function () {
      if (iframe.parentNode) {
        iframe.parentNode.removeChild(iframe);
      }
    }, 60000);
  }

  // Some iOS browsers (Orion) don't save a file from the hidden iframe: offer a link to tap.
  function showManualDownloadLink(url, filename) {
    var existing = byId('manual-download-banner');
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }

    var banner = document.createElement('div');
    banner.id = 'manual-download-banner';
    // No calc() or transforms (iOS 6): fixed width and a negative margin, as #toast.
    banner.style.cssText = 'position:fixed;bottom:20px;left:50%;margin-left:-150px;width:300px;background:#1e293b;border:1px solid rgba(148,163,184,0.3);border-radius:12px;-webkit-border-radius:12px;padding:0.85rem 1rem;box-shadow:0 10px 30px rgba(0,0,0,0.4);-webkit-box-shadow:0 10px 30px rgba(0,0,0,0.4);z-index:9998;font-size:0.9rem;color:#f8fafc;box-sizing:border-box;-webkit-box-sizing:border-box;';

    var header = document.createElement('div');
    header.style.cssText = 'display:-webkit-box;-webkit-box-align:start;-webkit-box-pack:justify;margin-bottom:0.6rem;';

    var label = document.createElement('div');
    label.style.cssText = 'color:rgba(226,232,240,0.8);line-height:1.3;-webkit-box-flex:1;';
    label.appendChild(document.createTextNode("If the download didn't start automatically:"));

    var closeBtn = document.createElement('button');
    closeBtn.setAttribute('type', 'button');
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.appendChild(document.createTextNode('\u2715'));
    closeBtn.className = 'banner-close';
    closeBtn.onclick = function () {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    };

    header.appendChild(label);
    header.appendChild(closeBtn);

    var link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    // word-wrap:break-word (not word-break:break-all) - much better old
    // WebKit support for wrapping a long unbreakable filename.
    link.style.cssText = 'display:block;color:#60a5fa;font-weight:600;text-decoration:none;word-wrap:break-word;line-height:1.4;';
    link.appendChild(document.createTextNode('Tap to download: ' + filename));

    banner.appendChild(header);
    banner.appendChild(link);
    document.body.appendChild(banner);

    // Don't let it linger forever if it's never dismissed manually.
    setTimeout(function () {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 5 * 60 * 1000);
  }

  // The itms-services prompt is reliable only for a tap: offer a link.
  // "10_3_4" from Safari's User-Agent -> [10, 3, 4]; null off iOS.
  function deviceIosVersion() {
    var match = /OS (\d+)_(\d+)(?:_(\d+))? like Mac OS X/.exec(navigator.userAgent || '');
    return match ? [parseInt(match[1], 10), parseInt(match[2], 10), parseInt(match[3] || '0', 10)] : null;
  }

  function versionLess(a, b) {
    for (var i = 0; i < Math.max(a.length, b.length); i += 1) {
      var x = a[i] || 0;
      var y = b[i] || 0;
      if (x !== y) {
        return x < y;
      }
    }
    return false;
  }

  function minimumOsWarning(job) {
    if (!job.minimumOsVersion) {
      return '';
    }
    var needed = job.minimumOsVersion.split('.');
    for (var i = 0; i < needed.length; i += 1) {
      needed[i] = parseInt(needed[i], 10) || 0;
    }
    var device = deviceIosVersion();
    if (device && versionLess(device, needed)) {
      return 'This version needs iOS ' + job.minimumOsVersion + ' or later, but this device runs iOS ' + device.join('.') + ' - iOS will refuse to install it. ';
    }
    return 'Requires iOS ' + job.minimumOsVersion + '+. ';
  }

  function showOtaInstall(job, filename) {
    var existing = byId('manual-download-banner');
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }
    var banner = document.createElement('div');
    banner.id = 'manual-download-banner';
    banner.style.cssText = 'position:fixed;bottom:20px;left:50%;margin-left:-150px;width:300px;background:#1e293b;border:1px solid rgba(148,163,184,0.3);border-radius:12px;-webkit-border-radius:12px;padding:0.85rem 1rem;z-index:9998;font-size:0.9rem;color:#f8fafc;box-sizing:border-box;-webkit-box-sizing:border-box;';

    var closeBtn = document.createElement('button');
    closeBtn.setAttribute('type', 'button');
    closeBtn.appendChild(document.createTextNode('\u2715'));
    closeBtn.className = 'banner-close float-right';
    closeBtn.onclick = function () {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    };

    var link = document.createElement('a');
    link.href = job.installUrl;
    link.style.cssText = 'display:block;color:#60a5fa;font-weight:600;text-decoration:none;word-wrap:break-word;line-height:1.4;margin:0.2rem 0 0.4rem;';
    link.appendChild(document.createTextNode('\uD83D\uDCF2 Tap to install: ' + filename));

    var note = document.createElement('div');
    note.style.cssText = 'color:rgba(226,232,240,0.75);line-height:1.35;font-size:0.8rem;';
    var noteText = minimumOsWarning(job) + (job.otaNeedsHttps ? 'Served over HTTP: works on iOS 6; iOS 7.1+ needs HTTPS.' : '');
    note.appendChild(document.createTextNode(noteText));

    banner.appendChild(closeBtn);
    banner.appendChild(link);
    if (noteText) {
      banner.appendChild(note);
    }
    document.body.appendChild(banner);
    setTimeout(function () {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 10 * 60 * 1000);

    try {
      window.location.href = job.installUrl;
    } catch (e) {
      // the visible link is the fallback
    }
  }

  function pollDownloadJob(jobId, filename, saveToServerFolder, installOta) {
    sendRequest('GET', apiUrl('/api/download-jobs/' + jobId), null, function (response) {
      var job = response.body || {};

      if (response.status === 404) {
        hideDownloadProgress();
        showToast('Download failed', true);
        return;
      }

      if (job.status === 'error') {
        hideDownloadProgress();
        showToast(job.error || 'Download failed', true);
        return;
      }

      if (job.filename) {
        filename = job.filename;
      }

      if (job.status === 'ready') {
        if (installOta && job.installUrl) {
          hideDownloadProgress();
          showOtaInstall(job, filename);
          return;
        }
        if (saveToServerFolder) {
          hideDownloadProgress();
          showToast('Saved on server: ' + (job.serverPath || filename));
          return;
        }
        var fileUrl = apiUrl('/api/download-jobs/' + jobId + '/file');
        updateDownloadProgress('Saving file...', filename);
        fetchFileViaHiddenIframe(fileUrl);
        showManualDownloadLink(fileUrl, filename);
        // No progress for an iframe download: just say it's handed off.
        setTimeout(function () {
          hideDownloadProgress();
          showToast('Downloading: ' + filename);
        }, 800);
        return;
      }

      if (job.phase === 'patching' || job.phase === 'finalizing') {
        // Downloaded; the server is adding metadata and the SINF (slow for big apps).
        var label = job.phase === 'patching' ? 'Patching package...' : 'Finalizing (adding signature)...';
        if (job.itemsTotal) {
          label += ' ' + job.itemsDone + ' / ' + job.itemsTotal + ' files';
        }
        updateDownloadProgress(label, filename);
      } else if (job.bytesTotal) {
        var percent = Math.floor((job.bytesDone / job.bytesTotal) * 100);
        updateDownloadProgress(percent + '% (' + formatBytes(job.bytesDone) + ' / ' + formatBytes(job.bytesTotal) + ')', filename);
      } else if (job.bytesDone) {
        updateDownloadProgress('Downloading... ' + formatBytes(job.bytesDone), filename);
      } else {
        updateDownloadProgress('Preparing download...', filename);
      }

      setTimeout(function () {
        pollDownloadJob(jobId, filename, saveToServerFolder, installOta);
      }, DOWNLOAD_POLL_INTERVAL_MS);
    });
  }

  function startDownloadJob(versionId, purchaseIfNeeded, saveToServerFolder, installOta) {
    if (!versionId) {
      return;
    }

    var payload = {
      externalVersionId: versionId
    };
    if (currentAppId) {
      payload.appId = currentAppId;
    }
    if (currentBundleId) {
      payload.bundleId = currentBundleId;
    }
    if (currentPlatform) {
      payload.platform = currentPlatform;
    }
    if (purchaseIfNeeded) {
      payload.purchaseIfNeeded = true;
    }
    if (saveToServerFolder) {
      payload.saveToServerFolder = true;
    }

    showToast(saveToServerFolder ? 'Starting server-side download...' : 'Starting download...');
    showDownloadProgress('Preparing download...');

    sendRequest('POST', apiUrl('/api/download-jobs'), payload, function (response) {
      var body = response.body || {};

      if (response.status < 200 || response.status >= 300 || !body.jobId) {
        var bodyError = body.error || '';
        var isLicenseError = body.licenseRequired || bodyError.toLowerCase().indexOf('license') !== -1 || (body.metadata && body.metadata.failureType === '9610');
        hideDownloadProgress();
        if (isLicenseError) {
          if (purchaseModal) {
            showPurchaseModal(currentAppId, currentBundleId);
          }
          showToast('License required for this download', true);
        } else {
          showToast(bodyError || 'Download failed', true);
        }
        return;
      }

      pollDownloadJob(body.jobId, 'app.ipa', saveToServerFolder, installOta);
    });
  }

  function downloadVersion(versionId, purchaseIfNeeded) {
    startDownloadJob(versionId, purchaseIfNeeded, false);
  }

  // Saves into ~/Downloads/IPATool on the server (for browsers that can't
  // receive a download, such as iOS 6 Safari).
  function downloadVersionToServer(versionId, purchaseIfNeeded) {
    startDownloadJob(versionId, purchaseIfNeeded, true);
  }

  function handleSearchFormSubmit(event) {
    if (event && event.preventDefault) {
      event.preventDefault();
    }
    runSearch();
    return false;
  }

  function handlePurchaseModalSubmit(event) {
    if (event && event.preventDefault) {
      event.preventDefault();
    }

    var formData = serializeForm(purchaseModalForm);
    var appId = formData.appId || currentAppId || '';
    var bundleId = formData.bundleId || currentBundleId || '';

    hidePurchaseModal();
    if (!appId && !bundleId) {
      showToast('Unable to acquire license', true);
      return false;
    }

    acquireLicenseAndRetry(appId, bundleId, currentExternalVersionId, currentPlatform);
    return false;
  }

  function handleDirectLookupSubmit(event) {
    if (event && event.preventDefault) {
      event.preventDefault();
    }

    var formData = serializeForm(directLookupForm);
    if (!formData.appId && !formData.bundleId) {
      showToast('Please provide App ID or Bundle ID', true);
      return false;
    }

    mergeCatalogs = formData.mergeCatalogs === 'on';
    loadAppVersions(formData.appId, formData.bundleId, formData.externalVersionId, formData.platform, formData.communityFallback === 'on', formData.catalogFirst === 'on');
    return false;
  }

  function attachEvents() {
    if (loginForm) {
      loginForm.onsubmit = function (event) {
        return handleLoginFormSubmit(event);
      };
    }

    if (authModalForm) {
      authModalForm.onsubmit = function (event) {
        return handleAuthModalSubmit(event);
      };
    }

    if (searchForm) {
      searchForm.onsubmit = function (event) {
        return handleSearchFormSubmit(event);
      };
    }

    if (directLookupForm) {
      directLookupForm.onsubmit = function (event) {
        return handleDirectLookupSubmit(event);
      };
    }

    bindPasswordToggles();

    var clearCacheButton = byId('clear-cache-button');
    if (clearCacheButton) {
      clearCacheButton.onclick = function () {
        clearCacheButton.disabled = true;
        sendRequest('POST', apiUrl('/api/cache/clear'), {}, function (response) {
          clearCacheButton.disabled = false;
          if (response.status >= 200 && response.status < 300 && response.body) {
            showToast('Cache cleared (' + response.body.cleared + ' entries)');
          } else {
            showToast((response.body && response.body.error) || 'Failed to clear the cache', true);
          }
        });
        return false;
      };
    }

    if (logoutButton) {
      logoutButton.onclick = function () {
        handleLogout();
        return false;
      };
    }

    if (addAccountButton) {
      addAccountButton.onclick = function () {
        handleAddAccount();
        return false;
      };
    }

    if (accountsToggle) {
      accountsToggle.onclick = function (event) {
        var e = event || window.event;
        if (e.stopPropagation) {
          e.stopPropagation();
        } else {
          e.cancelBubble = true;
        }
        setAccountsMenuOpen(!hasClass(accountsBox, 'open'));
        return false;
      };
    }
    if (document && document.addEventListener) {
      // iOS Safari sends no click for taps on plain text, so touchstart too.
      var closeOutside = function (e) {
        var node = e.target || e.srcElement;
        while (node) {
          if (node === accountsBox) {
            return;
          }
          node = node.parentNode;
        }
        setAccountsMenuOpen(false);
      };
      document.addEventListener('click', closeOutside, false);
      document.addEventListener('touchstart', closeOutside, false);
      document.addEventListener('keydown', function (e) {
        if ((e.keyCode === 27 || e.key === 'Escape') && accountsBox && hasClass(accountsBox, 'open')) {
          setAccountsMenuOpen(false);
        }
      }, false);
    }

    if (accountsList) {
      accountsList.onclick = function (event) {
        var e = event || window.event;
        var node = e.target || e.srcElement;
        while (node && node !== accountsList) {
          if (node.getAttribute && node.getAttribute('data-account-action')) {
            handleAccountAction(node.getAttribute('data-account-action'), node.getAttribute('data-account-id'));
            return false;
          }
          node = node.parentNode;
        }
        return true;
      };
    }

    if (authModalCancel) {
      authModalCancel.onclick = function () {
        hideAuthModal();
        pendingCredentials = null;
        return false;
      };
    }

    if (purchaseModalForm) {
      purchaseModalForm.onsubmit = function (event) {
        return handlePurchaseModalSubmit(event);
      };
    }

    if (purchaseModalCancel) {
      purchaseModalCancel.onclick = function () {
        hidePurchaseModal();
        return false;
      };
    }

    if (tabButtons) {
      for (var i = 0; i < tabButtons.length; i += 1) {
        var button = tabButtons[i];
        if (!button.getAttribute('data-tab')) {
          continue;
        }
        button.onclick = function () {
          switchTab(this.getAttribute('data-tab'));
          return false;
        };
      }
    }

    // Delegated click handler for copy buttons, download buttons, and version card toggles
    function delegatedClickHandler(e) {
      var target = e.target || e.srcElement;
      // Copy code
      var copyEl = target.closest ? target.closest('.copy-code') : findAncestorByClass(target, 'copy-code');
      if (copyEl) {
        try {
          var txt = copyEl.getAttribute('data-copy') || copyEl.textContent || '';
          copyTextToClipboard(txt.trim());
        } catch (err) {}
        e.stopPropagation && e.stopPropagation();
        e.preventDefault && e.preventDefault();
        return false;
      }

      // Download button
      var dl = target.closest ? target.closest('.download-version-btn') : findAncestorByClass(target, 'download-version-btn');
      if (dl) {
        var vid = dl.getAttribute('data-version-id');
        if (vid) {
          downloadVersion(vid, false);
        }
        e.stopPropagation && e.stopPropagation();
        e.preventDefault && e.preventDefault();
        return false;
      }

      // Save-on-server button
      var saveServer = target.closest ? target.closest('.save-server-btn') : findAncestorByClass(target, 'save-server-btn');
      if (saveServer) {
        var svid = saveServer.getAttribute('data-version-id');
        if (svid) {
          downloadVersionToServer(svid, false);
        }
        e.stopPropagation && e.stopPropagation();
        e.preventDefault && e.preventDefault();
        return false;
      }

      // Install over the air (itms-services)
      var ota = target.closest ? target.closest('.install-ota-btn') : findAncestorByClass(target, 'install-ota-btn');
      if (ota) {
        var ovid = ota.getAttribute('data-version-id');
        if (ovid) {
          startDownloadJob(ovid, false, false, true);
        }
        e.stopPropagation && e.stopPropagation();
        e.preventDefault && e.preventDefault();
        return false;
      }

      // Version header toggle
      var header = target.closest ? target.closest('.version-header') : findAncestorByClass(target, 'version-header');
      if (header) {
        var card = header.parentNode;
        toggleLegacyVersionCard(card);
        e.stopPropagation && e.stopPropagation();
        e.preventDefault && e.preventDefault();
        return false;
      }
      return true;
    }

    if (searchResults && searchResults.addEventListener) {
      searchResults.addEventListener('click', delegatedClickHandler, false);
    }
    if (versionsList && versionsList.addEventListener) {
      versionsList.addEventListener('click', delegatedClickHandler, false);
    }

    // Ensure tab clicks work even if per-button handlers fail (older browsers)
    if (document && document.addEventListener) {
      document.addEventListener('click', function (e) {
        var t = e.target || e.srcElement;
        var btn = findAncestorWithDataTab(t);
        if (btn) {
          try {
            switchTab(btn.getAttribute('data-tab'));
          } catch (err) {}
          if (e.preventDefault) e.preventDefault();
          if (e.stopPropagation) e.stopPropagation();
          return false;
        }
      }, false);
    }
  }

  // Helper for older browsers without Element.closest
  function findAncestorByClass(el, className) {
    var needle = ' ' + className + ' ';
    while (el) {
      if (el.className && (' ' + ('' + el.className) + ' ').indexOf(needle) !== -1) {
        return el;
      }
      el = el.parentNode;
    }
    return null;
  }

  function findAncestorWithDataTab(el) {
    while (el) {
      try {
        if (el.getAttribute && el.getAttribute('data-tab')) {
          return el;
        }
      } catch (e) {}
      el = el.parentNode;
    }
    return null;
  }

  function init() {
    loginForm = byId('login-form');
    logoutButton = byId('logout-button');
    accountBox = byId('account-info');
    accountsBox = byId('accounts-box');
    accountsList = byId('accounts-list');
    addAccountButton = byId('add-account-button');
    accountsToggle = byId('accounts-toggle');
    accountsCurrent = byId('accounts-current');
    toast = byId('toast');
    appFinderSection = byId('app-finder-section');
    versionsSection = byId('versions-section');
    authModal = byId('auth-modal');
    authModalForm = byId('auth-modal-form');
    authModalMessage = byId('auth-modal-message');
    authModalError = byId('auth-modal-error');
    authModalInput = byId('auth-modal-input');
    authModalCancel = byId('auth-modal-cancel');
    authCodeMessage = byId('auth-code-message');
    searchForm = byId('search-form');
    directLookupForm = byId('direct-lookup-form');
    searchResults = byId('search-results');
    versionsList = byId('versions-list');
    appTitle = byId('app-title');
    appSubtitle = byId('app-subtitle');
    communityFallbackCheckbox = byId('community-fallback-checkbox');
    directCommunityFallbackCheckbox = byId('direct-community-fallback-checkbox');
    searchTab = byId('search-tab');
    directTab = byId('direct-tab');
    var platformSelect = byId('platform-select');
    var directPlatformSelect = byId('direct-platform-select');
    var platformHint = byId('platform-hint');
    purchaseModal = byId('purchase-modal');
    purchaseModalForm = byId('purchase-modal-form');
    purchaseModalCancel = byId('purchase-modal-cancel');
    purchaseAppId = byId('purchase-app-id');
    purchaseBundleId = byId('purchase-bundle-id');
    downloadProgress = byId('download-progress');
    downloadProgressText = byId('download-progress-text');
    downloadProgressFilename = byId('download-progress-filename');
    tabButtons = document.getElementsByTagName('button');

    attachEvents();
    switchTab('search');
    setLoggedIn(false);
    refreshAccountState();

    // Apple TV hint toggle for legacy (shown only when 'appletv' is selected)
    if (platformSelect && platformHint) {
      try {
        platformSelect.onchange = function () {
          setElementHidden(platformHint, this.value !== 'appletv');
        };
        setElementHidden(platformHint, platformSelect.value !== 'appletv');
      } catch (e) {
        // ignore
      }
    }
    if (directPlatformSelect && platformHint) {
      try {
        directPlatformSelect.onchange = function () {
          setElementHidden(platformHint, this.value !== 'appletv');
        };
      } catch (e) {
        // ignore
      }
    }
  }

  if (document.readyState === 'loading') {
    if (document.addEventListener) {
      document.addEventListener('DOMContentLoaded', init, false);
    }
  } else {
    init();
  }
})();
