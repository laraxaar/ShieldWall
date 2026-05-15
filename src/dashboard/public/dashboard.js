/**
 * ShieldWall Dashboard — Frontend JavaScript
 * WebSocket client + DOM rendering for real-time attack monitoring
 */

(function() {
  'use strict';

  // ── State ──────────────────────────────────────────────
  const state = {
    connected: false,
    stats: { totalRequests: 0, blockedRequests: 0, detectedThreats: 0, rulesLoaded: 0, startTime: Date.now() },
    events: [],
    maxEvents: 200,
    severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    categories: {},
    ips: {},
    currentTab: 'overview',
    rules: [],
    activeRuleFile: null,
    editorContent: '',
    mapData: [],
  };

  // ── DOM Elements ───────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const el = {
    statusIndicator: $('#status-indicator'),
    statusText: $('#status-text'),
    uptime: $('#uptime'),
    statTotal: $('#stat-total'),
    statBlocked: $('#stat-blocked'),
    statThreats: $('#stat-threats'),
    statRules: $('#stat-rules'),
    feedList: $('#feed-list'),
    clearFeed: $('#clear-feed'),
    sevCritical: $('#sev-critical'),
    sevHigh: $('#sev-high'),
    sevMedium: $('#sev-medium'),
    sevLow: $('#sev-low'),
    sevCriticalCount: $('#sev-critical-count'),
    sevHighCount: $('#sev-high-count'),
    sevMediumCount: $('#sev-medium-count'),
    sevLowCount: $('#sev-low-count'),
    categoryList: $('#category-list'),
    ipList: $('#ip-list'),
    navBtns: document.querySelectorAll('.nav-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
    ruleFileList: $('#rule-file-list'),
    ruleEditor: $('#rule-editor'),
    saveRuleBtn: $('#save-rule'),
    currentFilename: $('#current-filename'),
    worldMap: $('#world-map'),
    mapStats: $('#map-stats'),
  };

  // ── Tab Switching ──────────────────────────────────────
  el.navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      switchTab(tab);
    });
  });

  function switchTab(tab) {
    state.currentTab = tab;
    el.navBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    el.tabContents.forEach(c => c.classList.toggle('active', c.id === `tab-${tab}`));
    
    if (tab === 'rules' && state.rules.length === 0) fetchRules();
    if (tab === 'map') fetchGeoData();
  }

  // ── Server-Sent Events (SSE) Connection ───────────────────────────────
  let evtSource = null;
  let reconnectTimer = null;

  function connect() {
    const protocol = location.protocol === 'https:' ? 'https:' : 'http:';
    // Use the backend URL if running via Live Server
    const backendUrl = location.port === '5500' && location.pathname.includes('dashboard') ? 'http://localhost:5500/api/live-logs' : '/api/live-logs';
    
    try {
      evtSource = new EventSource(backendUrl);
    } catch (e) {
      scheduleReconnect();
      return;
    }

    evtSource.onopen = () => {
      state.connected = true;
      el.statusIndicator.classList.add('active');
      el.statusText.textContent = 'Connected';
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    evtSource.onmessage = (event) => {
      // The heartbeat sends ': connected', which is an SSE comment and triggers onopen, 
      // but if we receive empty data or just heartbeat strings, we ignore.
      if (!event.data) return;

      try {
        const data = JSON.parse(event.data);
        if (data.type === 'sync' || data.type === 'attack' || data.type === 'feed') {
           handleMessage({ type: 'log', data: data.data || data });
        } else if (data.blocked !== undefined) {
           handleMessage({ type: 'log', data: data }); // For test:stress payload format
        } else {
           handleMessage(data); // Fallback
        }
      } catch (err) {
        console.error('SSE parsing error:', err);
      }
    };

    evtSource.onerror = () => {
      if (state.connected) {
        state.connected = false;
        el.statusIndicator.classList.remove('active');
        el.statusText.textContent = 'Reconnecting...';
        evtSource.close();
        scheduleReconnect();
      }
    };
  }

  function scheduleReconnect() {
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, 2000);
    }
  }

  // ── Message Handlers ───────────────────────────────────
  function handleMessage(msg) {
    switch (msg.type) {
      case 'init':
        if (msg.data.stats) Object.assign(state.stats, msg.data.stats);
        if (msg.data.recentEvents) {
          for (const evt of msg.data.recentEvents) processEvent(evt);
        }
        updateUI();
        break;

      case 'log':
        processEvent(msg.data);
        updateUI();
        break;

      case 'threat':
        if (msg.data.matches) {
          for (const match of msg.data.matches) {
            const evt = {
              type: 'attack',
              action: msg.data.blocked ? 'blocked' : 'detected',
              rule: match.rule,
              severity: match.severity,
              category: match.category,
              description: match.description,
              ip: msg.data.request?.ip || 'unknown',
              method: msg.data.request?.method || 'GET',
              url: msg.data.request?.url || '/',
              timestamp: new Date().toISOString(),
              geo: msg.data.geo || 'Unknown',
            };
            processEvent(evt);
            if (state.currentTab === 'map') addMapPoint(evt);
          }
        }
        state.stats.detectedThreats++;
        if (msg.data.blocked) state.stats.blockedRequests++;
        updateUI();
        break;
    }
  }

  function processEvent(evt) {
    if (evt.type !== 'attack') return;
    state.events.unshift(evt);
    if (state.events.length > state.maxEvents) state.events.pop();

    const sev = evt.severity || 'medium';
    if (state.severity[sev] !== undefined) state.severity[sev]++;

    const cat = evt.category || 'unknown';
    state.categories[cat] = (state.categories[cat] || 0) + 1;

    const ip = evt.ip || 'unknown';
    state.ips[ip] = (state.ips[ip] || 0) + 1;
  }

  // ── Rule Editor ────────────────────────────────────────
  function fetchRules() {
    fetch('/api/rules')
      .then(r => r.json())
      .then(rules => {
        state.rules = rules;
        const files = [...new Set(rules.map(r => r.source).filter(Boolean))];
        renderFileList(files);
      });
  }

  function renderFileList(files) {
    el.ruleFileList.innerHTML = files.map(f => `
      <div class="file-item" data-file="${f}">${f.split(/[\/\\]/).pop()}</div>
    `).join('');
    
    document.querySelectorAll('.file-item').forEach(item => {
      item.addEventListener('click', () => loadRuleFile(item.dataset.file));
    });
  }

  function loadRuleFile(filename) {
    document.querySelectorAll('.file-item').forEach(i => i.classList.toggle('active', i.dataset.file === filename));
    state.activeRuleFile = filename;
    el.currentFilename.textContent = filename.split(/[\/\\]/).pop();
    
    fetch(`/api/rules/content?file=${encodeURIComponent(filename)}`)
      .then(r => r.json())
      .then(data => {
        el.ruleEditor.value = data.content;
        state.editorContent = data.content;
        el.saveRuleBtn.disabled = false;
      });
  }

  el.saveRuleBtn.addEventListener('click', () => {
    if (!state.activeRuleFile) return;
    const content = el.ruleEditor.value;
    el.saveRuleBtn.disabled = true;
    el.saveRuleBtn.textContent = 'Saving...';

    fetch('/api/rules/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: state.activeRuleFile, content })
    })
    .then(r => r.json())
    .then(data => {
      el.saveRuleBtn.textContent = 'Save & Reload';
      el.saveRuleBtn.disabled = false;
      if (data.success) {
        alert('Rules reloaded successfully!');
        fetchRules(); // Refresh stats
      }
    });
  });

  // ── Map Visualization ──────────────────────────────────
  function fetchGeoData() {
    fetch('/api/geo-data')
      .then(r => r.json())
      .then(data => {
        state.mapData = data;
        renderMap();
      });
  }

  function renderMap() {
    el.worldMap.innerHTML = `
      <svg viewBox="0 0 1000 500" class="world-svg" style="width:100%; height:100%; opacity:0.1">
        <rect width="1000" height="500" fill="transparent"/>
        <!-- Basic continents simplified -->
        <path d="M150,100 L350,80 L400,150 L350,300 L200,350 Z" fill="white"/> <!-- N. America -->
        <path d="M300,350 L400,450 L500,400 L450,350 Z" fill="white"/> <!-- S. America -->
        <path d="M450,100 L650,50 L800,100 L700,250 L500,200 Z" fill="white"/> <!-- Eurasia -->
        <path d="M500,220 L600,250 L650,400 L550,450 L450,350 Z" fill="white"/> <!-- Africa -->
        <path d="M750,350 L850,320 L900,400 L800,420 Z" fill="white"/> <!-- Australia -->
      </svg>
      <div id="map-points-container"></div>
    `;
    state.mapData.forEach(addMapPoint);
    el.mapStats.textContent = `${state.mapData.length} Attack Vectors Logged`;
  }

  function addMapPoint(p) {
    const container = $('#map-points-container');
    if (!container) return;
    
    // Deterministic random positioning based on IP for mock map
    // (Real implementation would use Lat/Long projection)
    const seed = p.ip.split('.').reduce((a, b) => a + parseInt(b), 0);
    const x = (seed * 17) % 900 + 50;
    const y = (seed * 31) % 400 + 50;

    const dot = document.createElement('div');
    dot.className = `map-point map-point--pulsate`;
    dot.style.left = `${x / 10}%`;
    dot.style.top = `${y / 5}%`;
    dot.style.background = p.severity === 'critical' ? 'var(--critical)' : 'var(--high)';
    dot.style.boxShadow = `0 0 15px ${dot.style.background}`;
    
    container.appendChild(dot);
    
    // Remove old points to keep DOM clean
    if (container.children.length > 100) container.removeChild(container.firstChild);
  }

  // ── UI Rendering ───────────────────────────────────────
  function updateUI() {
    updateStats();
    updateFeed();
    updateSeverity();
    updateCategories();
    updateIPs();
  }

  function updateStats() {
    animateValue(el.statTotal, state.stats.totalRequests);
    animateValue(el.statBlocked, state.stats.blockedRequests);
    animateValue(el.statThreats, state.stats.detectedThreats);
    animateValue(el.statRules, state.stats.rulesLoaded || 0);
  }

  function animateValue(element, newValue) {
    const current = parseInt(element.textContent) || 0;
    if (current === newValue) return;
    element.textContent = newValue.toLocaleString();
    element.style.transform = 'scale(1.1)';
    setTimeout(() => element.style.transform = 'scale(1)', 300);
  }

  function updateFeed() {
    if (state.events.length === 0) {
      el.feedList.innerHTML = '<div class="feed-empty">Waiting for events...</div>';
      return;
    }

    const fragment = document.createDocumentFragment();
    state.events.slice(0, 50).forEach(evt => {
      const item = document.createElement('div');
      item.className = 'feed-item';
      const actionClass = evt.action === 'blocked' ? 'blocked' : 'detected';
      const actionLabel = evt.action === 'blocked' ? 'BLOCKED' : 'DETECTED';
      const time = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';

      item.innerHTML = `
        <div class="feed-item__severity feed-item__severity--${evt.severity || 'medium'}"></div>
        <div class="feed-item__content">
          <div class="feed-item__header">
            <span class="feed-item__rule">${escapeHTML(evt.rule || 'unknown')}</span>
            <span class="feed-item__action feed-item__action--${actionClass}">${actionLabel}</span>
          </div>
          <div class="feed-item__desc">${escapeHTML(evt.description || '')}</div>
          <div class="feed-item__meta">
            <span>🌐 ${escapeHTML(evt.ip || 'unknown')}</span>
            <span>📡 ${escapeHTML(evt.method || 'GET')} ${escapeHTML(truncate(evt.url || '/', 40))}</span>
            <span>🕐 ${time}</span>
          </div>
        </div>
      `;
      fragment.appendChild(item);
    });

    el.feedList.innerHTML = '';
    el.feedList.appendChild(fragment);
  }

  function updateSeverity() {
    const total = Object.values(state.severity).reduce((a, b) => a + b, 0) || 1;
    ['critical', 'high', 'medium', 'low'].forEach(level => {
      const count = state.severity[level] || 0;
      const pct = Math.min((count / total) * 100, 100);
      const bar = $(`#sev-${level}`);
      const countEl = $(`#sev-${level}-count`);
      if (bar) bar.style.width = `${pct}%`;
      if (countEl) countEl.textContent = count;
    });
  }

  function updateCategories() {
    const entries = Object.entries(state.categories).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (entries.length === 0) return;
    const icons = { 'sqli': '💉', 'xss': '🔴', 'traversal': '📁', 'cmdi': '⚡', 'scanner': '🤖' };
    el.categoryList.innerHTML = entries.map(([name, count]) => `
      <div class="category-item">
        <span class="category-item__name">${icons[name] || '🔹'} ${escapeHTML(name)}</span>
        <span class="category-item__count">${count}</span>
      </div>
    `).join('');
  }

  function updateIPs() {
    const entries = Object.entries(state.ips).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (entries.length === 0) return;
    el.ipList.innerHTML = entries.map(([ip, count]) => `
      <div class="ip-item"><span class="ip-item__addr">${escapeHTML(ip)}</span><span class="ip-item__count">${count}</span></div>
    `).join('');
  }

  function updateUptime() {
    const elapsed = Date.now() - (state.stats.startTime || Date.now());
    const h = Math.floor(elapsed / 3600000), m = Math.floor((elapsed % 3600000) / 60000), s = Math.floor((elapsed % 60000) / 1000);
    el.uptime.textContent = `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  function pad(n) { return n.toString().padStart(2, '0'); }
  function escapeHTML(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
  function truncate(str, maxLen) { return str.length > maxLen ? str.slice(0, maxLen) + '...' : str; }

  el.clearFeed.addEventListener('click', () => {
    state.events = [];
    state.severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    state.categories = {}; state.ips = {}; updateUI();
  });

  connect();
  setInterval(updateUptime, 1000);
  fetch('/api/stats').then(r => r.json()).then(data => { Object.assign(state.stats, data); updateStats(); });
  fetch('/api/history').then(r => r.json()).then(events => { events.forEach(processEvent); updateUI(); });

})();
