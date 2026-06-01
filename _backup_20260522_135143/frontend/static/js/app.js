'use strict';

/* ══ THÈME ═══════════════════════════════════════════════ */
const Theme = {
  get: () => localStorage.getItem('netsec-theme') || 'dark',
  set(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('netsec-theme', t);
    const icon = document.getElementById('theme-icon');
    if (icon) icon.className = t === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    if (window.Charts) Charts.updateTheme(t);
  },
  toggle() { this.set(this.get() === 'dark' ? 'light' : 'dark'); },
  init()   { this.set(this.get()); }
};

/* ══ NAVIGATION ══════════════════════════════════════════ */
const Nav = {
  _loaders: {},
  show(name, el) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const page = document.getElementById('page-' + name);
    if (!page) return;
    page.classList.add('active');
    if (el) el.classList.add('active');
    else {
      const n = document.getElementById('nav-' + name);
      if (n) n.classList.add('active');
    }
    if (this._loaders[name]) {
      try { this._loaders[name](); } catch(e) { console.warn('Nav loader error:', name, e); }
    }
  },
  register(name, fn) { this._loaders[name] = fn; }
};

/* ══ RECHERCHE TOPBAR ════════════════════════════════════ */
const Search = {
  map: {
    'device':'devices','appareil':'devices',
    'alert':'alerts','alerte':'alerts','ids':'alerts','snort':'alerts',
    'fire':'firewall','bloc':'firewall','nft':'firewall','whitelist':'firewall','blacklist':'firewall',
    'monit':'monitoring','cpu':'monitoring','ram':'monitoring','disk':'monitoring',
    'report':'reports','rapport':'reports',
    'ai':'ai-page','assist':'ai-page',
    'time':'timeline','log':'timeline',
    'dash':'dashboard','overview':'dashboard',
    'network':'network-topology','topol':'network-topology','map':'network-topology',
    'incident':'incidents',
    'threat':'threat-intel','intel':'threat-intel',
    'mitre':'mitre',
    'asset':'assets','inventaire':'assets',
    'terminal':'soc-terminal','term':'soc-terminal',
    'correl':'smart-correlations',
  },
  handle(val) {
    const v = (val || '').toLowerCase().trim();
    if (!v) return;
    for (const [kw, pg] of Object.entries(this.map)) {
      if (v.includes(kw)) { Nav.show(pg); return; }
    }
  }
};

/* ══ HELP MODAL ══════════════════════════════════════════ */
const Help = {
  toggle() { document.getElementById('help-modal')?.classList.toggle('open'); },
  close()  { document.getElementById('help-modal')?.classList.remove('open'); }
};

function helpSearch(q) {
  const v = (q || '').toLowerCase();
  document.querySelectorAll('.help-section').forEach(s => {
    s.style.display = (!v || s.textContent.toLowerCase().includes(v)) ? '' : 'none';
  });
}

function helpGoTo(id) {
  const el = document.getElementById('help-' + id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* ══ TOAST ═══════════════════════════════════════════════ */
const Toast = {
  show(msg, type = 'info', duration = 3500) {
    const colors = {
      success: 'var(--green)', error: 'var(--red)',
      info: 'var(--blue)', warn: 'var(--orange)',
    };
    const icons = {
      success: 'fa-check-circle', error: 'fa-exclamation-circle',
      info: 'fa-info-circle', warn: 'fa-exclamation-triangle',
    };
    const t = document.createElement('div');
    t.style.cssText = [
      'position:fixed;bottom:1.5rem;right:1.5rem',
      'background:var(--card);border:1px solid var(--border)',
      'border-radius:var(--radius-sm);padding:0.7rem 1rem',
      'font-size:0.78rem;box-shadow:var(--shadow);z-index:9999',
      'display:flex;align-items:center;gap:0.5rem',
      'min-width:220px;animation:slideInRight 0.3s ease',
      `border-left:3px solid ${colors[type] || colors.info}`,
    ].join(';');
    t.innerHTML = `<i class="fas ${icons[type] || icons.info}" style="color:${colors[type] || colors.info}"></i> ${msg}`;
    document.body.appendChild(t);
    setTimeout(() => {
      t.style.opacity = '0';
      t.style.transition = 'opacity 0.3s';
      setTimeout(() => t.remove(), 300);
    }, duration);
  }
};

/* ══ DATE TOPBAR ══════════════════════════════════════════ */
function initTopbarDate() {
  const el = document.getElementById('topbar-date');
  if (!el) return;
  const now  = new Date();
  const prev = new Date(now - 7 * 86400000);
  const fmt  = d => d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
  el.textContent = fmt(prev) + ' – ' + fmt(now);
}

/* ══ KPI FIREWALL (topbar) ═══════════════════════════════ */
function updateFirewallStats() {
  fetch('/api/firewall/stats')
    .then(r => r.json())
    .then(d => {
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('fw-blocked',    d.nb_bloques    || 0);
      set('fw-wl',         d.nb_whitelist  || 0);
      set('fw-bl',         d.nb_blacklist  || 0);
      set('fw-rules-count',d.nb_rules      || 0);
      set('kpi-blocked',   d.nb_bloques    || 0);
    })
    .catch(() => {});
}

/* ══ INSIGHTS ════════════════════════════════════════════ */
function loadInsights() {
  fetch('/api/intelligence/recommandations')
    .then(r => r.json())
    .then(data => {
      const def = [
        'Aucune anomalie critique détectée.',
        'Système en état stable.',
        'Aucune tendance suspecte.',
      ];
      ['ins-1', 'ins-2', 'ins-3'].forEach((id, i) => {
        const el = document.getElementById(id);
        if (el) el.textContent = data[i]?.description || data[i]?.titre || def[i];
      });
    })
    .catch(() => {});
}

/* ══ TIMELINE ════════════════════════════════════════════ */
function loadTimeline() {
  fetch('/api/intelligence/timeline')
    .then(r => r.json())
    .then(data => {
      const el = document.getElementById('timeline-list');
      if (!el) return;
      if (!data.length) {
        el.innerHTML = '<p class="no-data"><i class="fas fa-inbox"></i> Aucun événement</p>';
        return;
      }
      const colors = {
        CRITICAL: '#ef4444', HIGH: '#f59e0b',
        MEDIUM: '#ca8a04', LOW: '#3b82f6', BLOCKED: '#ef4444',
      };
      const icons = {
        ALERTE: 'fa-bell', IDS: 'fa-shield-virus',
        FIREWALL: 'fa-fire-alt', CORRELATION: 'fa-project-diagram',
      };
      el.innerHTML = data.map(t => {
        const col  = colors[t.niveau]  || '#3b82f6';
        const icon = icons[t.type_ev]  || 'fa-circle';
        return `<div style="display:flex;gap:0.9rem;padding:0.65rem 0.5rem;border-bottom:1px solid var(--border);align-items:flex-start">
          <div style="width:28px;height:28px;border-radius:50%;background:${col}14;border:1.5px solid ${col};display:flex;align-items:center;justify-content:center;font-size:0.68rem;color:${col};flex-shrink:0">
            <i class="fas ${icon}"></i>
          </div>
          <div style="flex:1;min-width:0">
            <div style="display:flex;justify-content:space-between;margin-bottom:0.12rem;gap:0.5rem;flex-wrap:wrap">
              <span style="font-size:0.7rem;font-weight:700;color:var(--blue)">${t.type_ev || '—'}</span>
              <span style="font-size:0.63rem;color:var(--muted);white-space:nowrap">${(t.ts || '').slice(0, 19)}</span>
            </div>
            <code>${t.ip || '—'}</code>
            <div style="font-size:0.68rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:360px;margin-top:0.1rem">${t.message || '—'}</div>
          </div>
          <span style="font-size:0.6rem;font-weight:700;padding:0.15rem 0.45rem;border-radius:20px;background:${col}14;color:${col};white-space:nowrap;flex-shrink:0;border:1px solid ${col}25">${t.niveau || '—'}</span>
        </div>`;
      }).join('');
    })
    .catch(() => {
      const el = document.getElementById('timeline-list');
      if (el) el.innerHTML = '<p class="no-data">Erreur chargement timeline</p>';
    });
}

/* ══ AI PAGE RESUME ══════════════════════════════════════ */
function loadAISysResume() {
  fetch('/ai/resume')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('ai-sys-resume');
      if (!el) return;
      const sc  = d.score || 0;
      const col = sc >= 80 ? '#10b981' : sc >= 60 ? '#f59e0b' : '#ef4444';
      const lbl = sc >= 80 ? 'SAFE'    : sc >= 60 ? 'WARNING' : 'DANGER';
      el.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem;margin-bottom:0.8rem">
          ${[
            [sc + '/100',           'Score',    col],
            [d.nb_appareils || 0,   'Devices',  'var(--blue)'],
            [d.nb_critical  || 0,   'Critiques','var(--red)'],
            [d.nb_bloques   || 0,   'Bloquées', 'var(--purple)'],
          ].map(([v, l, c]) => `
            <div style="background:var(--card2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:0.6rem;text-align:center">
              <div style="font-size:1.2rem;font-weight:800;color:${c}">${v}</div>
              <div style="font-size:0.6rem;color:var(--muted);text-transform:uppercase;font-weight:700">${l}</div>
            </div>`).join('')}
        </div>
        <div style="background:${sc >= 80 ? 'rgba(16,185,129,0.08)' : sc >= 60 ? 'rgba(245,158,11,0.08)' : 'rgba(239,68,68,0.08)'};border:1px solid ${col}30;border-radius:var(--radius-sm);padding:0.6rem;text-align:center;font-size:0.78rem;font-weight:700;color:${col}">
          <i class="fas fa-circle" style="font-size:0.5rem;margin-right:0.3rem"></i> Statut : ${lbl}
        </div>`;
    })
    .catch(() => {});
}

/* ══ CORRÉLATIONS ════════════════════════════════════════ */
function loadCorrelations() {
  fetch('/api/intelligence/correlations')
    .then(r => r.json())
    .then(data => {
      const el = document.getElementById('correlation-list');
      if (!el) return;
      if (!data.length) {
        el.innerHTML = '<p class="no-data"><i class="fas fa-check-circle" style="color:var(--green)"></i> Aucune corrélation</p>';
        return;
      }
      el.innerHTML = data.map(e => {
        const col = e.severite === 'CRITICAL' ? 'var(--red)' : 'var(--orange)';
        return `<div style="display:flex;align-items:center;gap:0.75rem;padding:0.6rem 0.85rem;border-radius:var(--radius-sm);margin-bottom:0.35rem;background:var(--card2);border:1px solid var(--border);border-left:2px solid ${col}">
          <i class="fas fa-project-diagram" style="color:${col}"></i>
          <div style="flex:1;min-width:0">
            <div style="font-size:0.75rem;font-weight:600">${e.rule_nom || '—'}</div>
            <div style="font-size:0.65rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${e.explication || '—'}</div>
          </div>
          <code>${e.ip || '—'}</code>
          <span class="badge badge-${e.severite === 'CRITICAL' ? 'critical' : 'high'}">${e.severite || '—'}</span>
        </div>`;
      }).join('');
    })
    .catch(() => {});
}

/* ══ REPORTS ═════════════════════════════════════════════ */
function loadReports() {
  fetch('/api/rapports')
    .then(r => r.json())
    .then(rapports => {
      const tbody = document.getElementById('reports-tbody');
      if (!tbody) return;
      if (!rapports.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="no-data">
          <i class="fas fa-folder-open" style="color:var(--muted)"></i>
          Aucun rapport — cliquez sur "Nouveau rapport"
        </td></tr>`;
        return;
      }
      tbody.innerHTML = rapports.map(r => `
        <tr class="report-row" data-date="${r.date_creation || ''}">
          <td style="color:var(--muted);font-weight:600">#${r.id}</td>
          <td style="color:var(--muted);font-size:0.72rem;white-space:nowrap">${(r.date_creation || '').slice(0, 19)}</td>
          <td style="font-size:0.78rem">${r.titre || 'Rapport SOC'}</td>
          <td><span class="badge badge-info"><i class="fas fa-desktop"></i> ${r.nb_appareils || 0}</span></td>
          <td>
            <span class="badge ${(r.score_global || 0) >= 80 ? 'badge-safe' : (r.score_global || 0) >= 60 ? 'badge-medium' : 'badge-critical'}">
              Score: ${r.score_global || 0}/100
            </span>
          </td>
          <td>
            <a href="/generer-rapport" target="_blank" class="action-btn green" title="Télécharger PDF">
              <i class="fas fa-file-pdf"></i> PDF
            </a>
          </td>
        </tr>`).join('');
    })
    .catch(() => {});
}

function generateReport() {
  const btn = document.getElementById('btn-gen-report');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Génération...';
  }
  // Ouvrir dans nouvel onglet + déclenchement download
  window.open('/generer-rapport', '_blank');
  // Recharger la liste après délai
  setTimeout(() => {
    loadReports();
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-plus"></i> Nouveau rapport';
    }
    Toast.show('Rapport PDF généré !', 'success');
  }, 2500);
}

function filterReports(type, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const rows = document.querySelectorAll('.report-row');
  const now  = new Date();
  rows.forEach(row => {
    if (type === 'all') { row.style.display = ''; return; }
    const d = new Date(row.dataset.date);
    row.style.display = (!isNaN(d) && now - d < 7 * 86400000) ? '' : 'none';
  });
}

/* ══ NETWORK TOPOLOGY ════════════════════════════════════ */
function initTopology() {
  const svg = document.getElementById('topology-svg');
  if (!svg) return;
  const nodes = [
    { id: 'fw',  x: 300, y: 140, color: '#ef4444', label: 'Firewall'  },
    { id: 'r1',  x: 150, y:  80, color: '#f59e0b', label: 'Router'    },
    { id: 'sw1', x: 150, y: 200, color: '#3b82f6', label: 'Switch'    },
    { id: 's1',  x:  50, y:  60, color: '#10b981', label: 'SRV-01'    },
    { id: 's2',  x:  50, y: 140, color: '#10b981', label: 'SRV-02'    },
    { id: 's3',  x:  50, y: 220, color: '#8b5cf6', label: 'DB-01'     },
    { id: 'ext', x: 450, y: 140, color: '#6b7280', label: 'Internet'  },
    { id: 'att', x: 520, y:  80, color: '#ef4444', label: 'Attaque'   },
  ];
  const links = [
    { from: 'fw',  to: 'r1',  threat: false },
    { from: 'fw',  to: 'sw1', threat: false },
    { from: 'r1',  to: 's1',  threat: false },
    { from: 'sw1', to: 's2',  threat: false },
    { from: 'sw1', to: 's3',  threat: false },
    { from: 'fw',  to: 'ext', threat: false },
    { from: 'ext', to: 'att', threat: true  },
  ];
  const map = {};
  nodes.forEach(n => (map[n.id] = n));
  let html = '';
  links.forEach(l => {
    const a = map[l.from], b = map[l.to];
    if (!a || !b) return;
    html += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"
      class="topo-link${l.threat ? ' threat' : ' active'}"/>`;
  });
  nodes.forEach(n => {
    html += `<g class="topo-node" onclick="Toast.show('Node: ${n.label}','info',1500)" style="cursor:pointer">
      <circle cx="${n.x}" cy="${n.y}" r="22" fill="${n.color}18" stroke="${n.color}" stroke-width="1.5"/>
      <text x="${n.x}" y="${n.y + 5}" text-anchor="middle" style="fill:${n.color};font-size:9px;font-weight:600;font-family:monospace">${n.label.slice(0, 4)}</text>
      <text x="${n.x}" y="${n.y + 36}" text-anchor="middle" class="topo-label" style="font-size:8px;fill:var(--muted)">${n.label}</text>
    </g>`;
  });
  svg.innerHTML = html;
  // Top ports chart
  if (window.Charts) {
    try { Charts.buildTopPorts(); } catch (e) {}
  }
}

/* ══ SOC TERMINAL ════════════════════════════════════════ */
const Terminal = {
  logs: [
    { t: 'info',    msg: '[INIT] Smart NetSec SOC Platform v3.0 démarrée' },
    { t: 'success', msg: '[OK] nftables actif — table netsec_filter chargée' },
    { t: 'info',    msg: '[IDS] Snort 3 en mode surveillance — eth0' },
    { t: 'info',    msg: '[NET] Interface eth0 — 192.168.216.0/24' },
    { t: 'warn',    msg: '[WARN] Port 445 (SMB) détecté sur 192.168.216.1' },
    { t: 'error',   msg: '[ALERT] Scan Nmap depuis 192.168.216.50 — SID:9000001' },
    { t: 'info',    msg: '[IDS] Règle ET SCAN déclenchée' },
    { t: 'warn',    msg: '[FW] Tentative SSH non autorisée — 192.168.216.50:44444' },
    { t: 'success', msg: '[FW] AUTO-BLOCK: 192.168.216.50 bloquée via nftables' },
    { t: 'info',    msg: '[CORR] Corrélation Scan+BruteForce détectée' },
    { t: 'error',   msg: '[CRITICAL] EternalBlue pattern détecté — SID:9000003' },
    { t: 'success', msg: '[BLOCK] Règle nftables: drop ip saddr 192.168.216.50' },
    { t: 'info',    msg: '[SCORE] Score sécurité recalculé — 78/100' },
    { t: 'info',    msg: '[DB] Rapport généré et sauvegardé en SQLite' },
  ],
  idx: 0,
  iv: null,
  start() {
    const body = document.getElementById('term-body');
    if (!body || this.iv) return;
    this.iv = setInterval(() => {
      const log  = this.logs[this.idx++ % this.logs.length];
      const time = new Date().toLocaleTimeString('fr-FR');
      const line = document.createElement('div');
      line.className = `term-line ${log.t}`;
      line.innerHTML = `<span style="color:var(--muted)">${time}</span> ${log.msg}`;
      body.appendChild(line);
      if (body.children.length > 60) body.removeChild(body.firstChild);
      body.scrollTop = body.scrollHeight;
    }, 2200);
  },
  stop() { if (this.iv) { clearInterval(this.iv); this.iv = null; } }
};

/* ══ INCIDENTS ═══════════════════════════════════════════ */
const _IncidentsStatic = [
  { id: 'INC-001', title: 'Scan réseau massif détecté',       severity: 'critical',  status: 'investigating', analyst: 'Admin',  time: '14:02', ip: '192.168.216.50'  },
  { id: 'INC-002', title: 'Tentative brute force SSH',        severity: 'high',      status: 'mitigated',     analyst: 'Admin',  time: '13:45', ip: '192.168.216.1'   },
  { id: 'INC-003', title: 'Port SMB exposé — risque EternalBlue', severity: 'high', status: 'open',          analyst: '—',      time: '12:30', ip: '192.168.216.1'   },
  { id: 'INC-004', title: 'Trafic DNS suspect vers externe',  severity: 'medium',    status: 'resolved',      analyst: 'Admin',  time: '11:15', ip: '192.168.216.2'   },
];

function loadIncidents() {
  const el = document.getElementById('incidents-list');
  if (!el) return;
  const sc = { critical: 'var(--red)', high: 'var(--orange)', medium: '#ca8a04', low: 'var(--blue)' };
  const sb = { investigating: 'badge-high', mitigated: 'badge-info', resolved: 'badge-safe', open: 'badge-critical' };
  el.innerHTML = _IncidentsStatic.map(inc => `
    <div class="incident-row" style="display:flex;align-items:center;gap:0.75rem;padding:0.65rem 0.85rem;border-radius:var(--radius-sm);margin-bottom:0.35rem;background:var(--card2);border:1px solid var(--border);border-left:2px solid ${sc[inc.severity]}">
      <div style="width:32px;height:32px;border-radius:var(--radius-sm);background:${sc[inc.severity]}14;color:${sc[inc.severity]};display:flex;align-items:center;justify-content:center;font-size:0.9rem;flex-shrink:0">
        <i class="fas fa-${inc.severity === 'critical' ? 'skull' : inc.severity === 'high' ? 'exclamation-triangle' : 'exclamation-circle'}"></i>
      </div>
      <div style="flex:1;min-width:0">
        <div style="font-size:0.78rem;font-weight:600;margin-bottom:0.12rem">${inc.title}</div>
        <div style="font-size:0.65rem;color:var(--muted);display:flex;gap:0.75rem;flex-wrap:wrap">
          <span style="color:${sc[inc.severity]};font-weight:700">${inc.severity.toUpperCase()}</span>
          <span><i class="fas fa-map-marker-alt"></i> ${inc.ip}</span>
          <span><i class="fas fa-clock"></i> ${inc.time}</span>
          <span><i class="fas fa-user"></i> ${inc.analyst}</span>
        </div>
      </div>
      <span class="badge ${sb[inc.status] || 'badge-info'}">${inc.status}</span>
    </div>`).join('');
}

/* ══ THREAT INTEL ════════════════════════════════════════ */
const _ThreatData = [
  { ip: '185.220.101.45', country: 'RU', flag: '🇷🇺', type: 'Tor Exit Node',  score: 95, level: 'critical' },
  { ip: '45.142.212.18',  country: 'NL', flag: '🇳🇱', type: 'Port Scanner',   score: 82, level: 'high'     },
  { ip: '89.248.167.131', country: 'NL', flag: '🇳🇱', type: 'Botnet C2',      score: 91, level: 'critical' },
  { ip: '103.35.74.55',   country: 'CN', flag: '🇨🇳', type: 'Brute Force',    score: 78, level: 'high'     },
  { ip: '192.168.216.50', country: '—',  flag: '🔴',  type: 'Scan interne',   score: 65, level: 'medium'   },
];

function loadThreatIntel() {
  const el = document.getElementById('threat-intel-list');
  if (!el) return;
  const col = { critical: '#ef4444', high: '#f59e0b', medium: '#ca8a04', low: '#3b82f6' };
  el.innerHTML = _ThreatData.map(t => `
    <div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border)">
      <span style="font-size:1rem">${t.flag}</span>
      <code style="color:var(--red);min-width:130px;font-size:0.75rem">${t.ip}</code>
      <div style="flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden">
        <div style="height:100%;width:${t.score}%;background:${col[t.level]};border-radius:2px"></div>
      </div>
      <span style="font-size:0.65rem;font-weight:700;color:${col[t.level]};min-width:26px;text-align:right">${t.score}</span>
      <span style="font-size:0.62rem;color:var(--muted);white-space:nowrap;min-width:80px">${t.type}</span>
      <span class="badge badge-${t.level}">${t.level.toUpperCase()}</span>
    </div>`).join('');
}

/* ══ ASSETS ══════════════════════════════════════════════ */
const _AssetsData = [
  { name: 'FW-MAIN',  type: 'Firewall',       ip: '192.168.216.1',   status: 'online',  icon: 'fa-fire-alt',      col: '#ef4444' },
  { name: 'SW-CORE',  type: 'Switch',          ip: '192.168.216.2',   status: 'online',  icon: 'fa-network-wired', col: '#f59e0b' },
  { name: 'SRV-WEB',  type: 'Serveur Web',     ip: '192.168.216.10',  status: 'online',  icon: 'fa-server',        col: '#10b981' },
  { name: 'SRV-DB',   type: 'Base de données', ip: '192.168.216.11',  status: 'warning', icon: 'fa-database',      col: '#8b5cf6' },
  { name: 'KALI-01',  type: 'Endpoint',        ip: '192.168.216.143', status: 'online',  icon: 'fa-laptop',        col: '#3b82f6' },
  { name: 'VM-WIN',   type: 'Windows VM',      ip: '192.168.216.50',  status: 'offline', icon: 'fa-desktop',       col: '#6b7280' },
];

function loadAssets() {
  const el = document.getElementById('assets-list');
  if (!el) return;
  const sc = { online: '#10b981', warning: '#f59e0b', offline: '#ef4444' };
  const sb = { online: 'badge-safe', warning: 'badge-high', offline: 'badge-critical' };
  el.innerHTML = _AssetsData.map(a => `
    <div style="display:flex;align-items:center;gap:0.75rem;padding:0.65rem 0.85rem;border-bottom:1px solid var(--border)">
      <div style="width:36px;height:36px;border-radius:var(--radius-sm);background:${a.col}14;color:${a.col};display:flex;align-items:center;justify-content:center;font-size:0.95rem;flex-shrink:0">
        <i class="fas ${a.icon}"></i>
      </div>
      <div style="flex:1;min-width:0">
        <div style="font-size:0.8rem;font-weight:600">${a.name}</div>
        <div style="font-size:0.65rem;color:var(--muted)">${a.type} — <code>${a.ip}</code></div>
      </div>
      <span class="badge ${sb[a.status]}">
        <span style="width:5px;height:5px;border-radius:50%;background:${sc[a.status]};display:inline-block;margin-right:2px"></span>
        ${a.status.toUpperCase()}
      </span>
    </div>`).join('');
}

/* ══ MITRE ATT&CK ════════════════════════════════════════ */
const _MitreData = [
  { phase: 'Reconnaissance', color: '#6b7280', techs: ['T1595 Scan', 'T1590 Gather Info'] },
  { phase: 'Resource Dev',   color: '#8b5cf6', techs: ['T1588 Tools', 'T1583 Infra']       },
  { phase: 'Initial Access', color: '#ef4444', techs: ['T1190 Exploit', 'T1078 Accounts']  },
  { phase: 'Execution',      color: '#f59e0b', techs: ['T1059 CLI', 'T1053 Scheduler']     },
  { phase: 'Persistence',    color: '#f59e0b', techs: ['T1547 Boot', 'T1136 Account']      },
  { phase: 'Privilege Esc',  color: '#ec4899', techs: ['T1068 Exploit', 'T1055 Inject']    },
  { phase: 'Defense Eva',    color: '#06b6d4', techs: ['T1027 Obfusc.', 'T1070 Remove']   },
  { phase: 'Lateral Move',   color: '#3b82f6', techs: ['T1021 Remote', 'T1210 Exploit']    },
  { phase: 'Exfiltration',   color: '#10b981', techs: ['T1041 C2', 'T1048 Alt Proto']      },
];
const _activePhases = ['Initial Access', 'Execution', 'Defense Eva'];

function loadMitre() {
  const el = document.getElementById('mitre-container');
  if (!el) return;
  el.innerHTML = _MitreData.map(p => {
    const active = _activePhases.includes(p.phase);
    return `<div class="mitre-phase" style="${active ? `border-color:${p.color};box-shadow:0 0 12px ${p.color}30` : ''}">
      <div class="mitre-phase-name" style="${active ? `color:${p.color}` : ''}">${p.phase}</div>
      ${p.techs.map(t => `<div class="mitre-technique ${active ? 'active' : ''}" style="${active ? `border-color:${p.color};color:${p.color}` : ''}">${t}</div>`).join('')}
    </div>`;
  }).join('');
}

/* ══ MONITORING ══════════════════════════════════════════ */
function updateMonitoring() {
  fetch('/api/supervision')
    .then(r => r.json())
    .then(data => {
      const s   = data.systeme || {};
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      const bar = (id, pct, col) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.style.width      = Math.min(100, pct || 0) + '%';
        el.style.background = (pct > 85) ? '#ef4444' : (pct > 65) ? '#f59e0b' : col;
      };

      set('cpu-val', (s.cpu  || 0) + '%');
      bar('cpu-bar', s.cpu  || 0, '#3b82f6');

      set('ram-val',    (s.ram_pct  || 0) + '%');
      bar('ram-bar',     s.ram_pct  || 0, '#8b5cf6');
      set('ram-detail', (s.ram_used || 0) + ' MB / ' + (s.ram_total || 0) + ' MB');

      set('disk-val',    (s.disk_pct  || 0) + '%');
      bar('disk-bar',     s.disk_pct  || 0, '#f59e0b');
      set('disk-detail', (s.disk_used || 0) + ' GB / ' + (s.disk_total || 0) + ' GB');

      set('net-up',   '↑ ' + (s.bytes_sent || 0) + ' KB');
      set('net-down', '↓ ' + (s.bytes_recv || 0) + ' KB');

      const st = document.getElementById('sys-statut');
      if (st) {
        st.textContent = data.statut || 'NORMAL';
        st.className = 'badge ' + (data.statut === 'NORMAL' ? 'badge-safe' :
                                   data.statut === 'WARNING'  ? 'badge-high' : 'badge-critical');
      }
      if (window.Charts) {
        try { Charts.updateMonitoring(s); } catch (e) {}
      }
    })
    .catch(() => {});
}

/* ══════════════════════════════════════════════════════════
   FIREWALL MODULE — nftables management
   ══════════════════════════════════════════════════════════ */
const FW = (() => {

  function showTab(tab) {
    document.querySelectorAll('.fw-panel').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.fw-tab-btn').forEach(b => {
      b.style.borderBottomColor = 'transparent';
      b.style.color = 'var(--muted)';
    });
    const panel = document.getElementById('fw-panel-' + tab);
    const btn   = document.getElementById('fw-tab-'   + tab);
    if (panel) panel.style.display = '';
    if (btn)   { btn.style.borderBottomColor = 'var(--blue)'; btn.style.color = 'var(--blue)'; }
    const loaders = {
      blocked:     loadBlocked,
      rules:       loadRules,
      whitelist:   loadWhitelist,
      blacklist:   loadBlacklist,
      connections: loadConnections,
      logs:        loadLogs,
    };
    if (loaders[tab]) loaders[tab]();
  }

  /* ── IPs Bloquées ─────────────────────────────────────── */
  function loadBlocked() {
    fetch('/api/firewall/stats')
      .then(r => r.json())
      .then(data => {
        const s = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
        s('fw-blocked',     data.nb_bloques  || 0);
        s('fw-wl',          data.nb_whitelist|| 0);
        s('fw-bl',          data.nb_blacklist|| 0);
        s('fw-rules-count', data.nb_rules    || 0);
        s('kpi-blocked',    data.nb_bloques  || 0);

        const tbody = document.getElementById('fw-blocked-tbody');
        if (!tbody) return;
        const bl = data.blocages || [];
        if (!bl.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-data"><i class="fas fa-check-circle" style="color:var(--green)"></i> Aucune IP bloquée</td></tr>';
          return;
        }
        tbody.innerHTML = bl.map(b => `
          <tr>
            <td><code>${b.ip}</code></td>
            <td style="font-size:0.72rem;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${b.raison || ''}">${b.raison || '—'}</td>
            <td><span class="badge badge-${b.niveau === 'CRITICAL' ? 'critical' : b.niveau === 'HIGH' ? 'high' : 'info'}">${b.niveau || '—'}</span></td>
            <td><span style="font-size:0.7rem;color:${b.auto_block ? 'var(--orange)' : 'var(--muted)'}">${b.auto_block ? 'AUTO' : 'Manuel'}</span></td>
            <td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">${(b.date_blocage || '').slice(0, 16)}</td>
            <td><button class="action-btn green" onclick="FW.unblock('${b.ip}')" title="Débloquer"><i class="fas fa-unlock"></i></button></td>
          </tr>`).join('');
      })
      .catch(e => console.error('FW loadBlocked:', e));
  }

  /* ── Règles nftables ─────────────────────────────────── */
  function loadRules() {
    fetch('/api/firewall/rules')
      .then(r => r.json())
      .then(rules => {
        const tbody = document.getElementById('fw-rules-tbody');
        if (!tbody) return;
        if (!rules.length) {
          tbody.innerHTML = '<tr><td colspan="10" class="no-data">Aucune règle enregistrée</td></tr>';
          return;
        }
        tbody.innerHTML = rules.map(r => `
          <tr>
            <td style="font-size:0.62rem;color:var(--muted);max-width:80px;overflow:hidden;text-overflow:ellipsis">${r.rule_id || '—'}</td>
            <td><span class="badge badge-${r.type === 'BLOCK' ? 'critical' : r.type === 'ALLOW' ? 'safe' : 'info'}">${r.type || '—'}</span></td>
            <td><code>${r.ip || '*'}</code></td>
            <td style="font-size:0.72rem">${r.port || '*'}</td>
            <td><span class="badge badge-info">${r.protocole || 'all'}</span></td>
            <td style="font-size:0.72rem;color:var(--muted)">${r.direction || 'INPUT'}</td>
            <td style="font-size:0.72rem">${r.priorite || 100}</td>
            <td><span class="badge ${r.actif ? 'badge-safe' : 'badge-medium'}">${r.actif ? 'Actif' : 'Inactif'}</span></td>
            <td style="color:var(--muted);font-size:0.62rem;white-space:nowrap">${(r.date_create || '').slice(0, 16)}</td>
            <td style="white-space:nowrap">
              <button class="action-btn" onclick="FW.toggleRule('${r.rule_id}',${r.actif ? 0 : 1})" title="${r.actif ? 'Désactiver' : 'Activer'}">
                <i class="fas fa-${r.actif ? 'pause' : 'play'}"></i>
              </button>
              <button class="action-btn red" onclick="FW.deleteRule('${r.rule_id}')" title="Supprimer">
                <i class="fas fa-trash"></i>
              </button>
            </td>
          </tr>`).join('');
      })
      .catch(e => console.error('FW loadRules:', e));
  }

  /* ── Whitelist ───────────────────────────────────────── */
  function loadWhitelist() {
    fetch('/api/firewall/whitelist')
      .then(r => r.json())
      .then(list => {
        const tbody = document.getElementById('fw-wl-tbody');
        if (!tbody) return;
        if (!list.length) {
          tbody.innerHTML = '<tr><td colspan="4" class="no-data">Whitelist vide</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(w => `
          <tr>
            <td><code style="color:var(--green)">${w.ip}</code></td>
            <td style="font-size:0.72rem;color:var(--muted)">${w.raison || '—'}</td>
            <td style="color:var(--muted);font-size:0.65rem">${(w.date_ajout || '').slice(0, 16)}</td>
            <td><button class="action-btn red" onclick="FW.removeWhitelist('${w.ip}')" title="Retirer"><i class="fas fa-times"></i></button></td>
          </tr>`).join('');
      })
      .catch(e => console.error('FW loadWhitelist:', e));
  }

  /* ── Blacklist ───────────────────────────────────────── */
  function loadBlacklist() {
    fetch('/api/firewall/blacklist')
      .then(r => r.json())
      .then(list => {
        const tbody = document.getElementById('fw-bl-tbody');
        if (!tbody) return;
        if (!list.length) {
          tbody.innerHTML = '<tr><td colspan="5" class="no-data">Blacklist vide</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(b => `
          <tr>
            <td><code style="color:var(--red)">${b.ip}</code></td>
            <td style="font-size:0.72rem;color:var(--muted)">${b.raison || '—'}</td>
            <td style="font-size:0.7rem;color:var(--muted)">${b.source || 'manual'}</td>
            <td style="color:var(--muted);font-size:0.65rem">${(b.date_ajout || '').slice(0, 16)}</td>
            <td>
              <button class="action-btn red" onclick="FW.block('${b.ip}','Blacklist')" title="Bloquer">
                <i class="fas fa-ban"></i>
              </button>
            </td>
          </tr>`).join('');
      })
      .catch(e => console.error('FW loadBlacklist:', e));
  }

  /* ── Connexions Live ─────────────────────────────────── */
  function loadConnections() {
    const tbody = document.getElementById('fw-conn-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="8" class="no-data"><i class="fas fa-spinner fa-spin"></i> Chargement...</td></tr>';
    fetch('/api/firewall/connections')
      .then(r => r.json())
      .then(conns => {
        if (!conns.length) {
          tbody.innerHTML = '<tr><td colspan="8" class="no-data">Aucune connexion active</td></tr>';
          return;
        }
        tbody.innerHTML = conns.map(c => `
          <tr style="${c.suspicious ? 'background:rgba(239,68,68,0.06)' : ''}">
            <td><span class="badge badge-info">${c.proto}</span></td>
            <td style="font-size:0.7rem;color:var(--muted)">${c.state || '—'}</td>
            <td><code>${c.local_ip}</code></td>
            <td style="font-size:0.72rem">${c.local_port}</td>
            <td><code style="color:${c.suspicious ? 'var(--red)' : 'inherit'}">${c.remote_ip}</code></td>
            <td style="font-size:0.72rem">${c.remote_port}</td>
            <td style="font-size:0.7rem;color:var(--muted)">${c.process || '—'}</td>
            <td>${c.suspicious ? '<span class="badge badge-critical">SUSPECT</span>' : '<span class="badge badge-safe">OK</span>'}</td>
          </tr>`).join('');
      })
      .catch(() => {
        tbody.innerHTML = '<tr><td colspan="8" class="no-data">Erreur chargement connexions</td></tr>';
      });
  }

  /* ── Logs ────────────────────────────────────────────── */
  function loadLogs() {
    fetch('/api/firewall/logs?limit=50')
      .then(r => r.json())
      .then(logs => {
        const tbody = document.getElementById('fw-logs-tbody');
        if (!tbody) return;
        if (!logs.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-data">Aucun log firewall</td></tr>';
          return;
        }
        tbody.innerHTML = logs.map(l => `
          <tr>
            <td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">${(l.timestamp || '').slice(0, 19)}</td>
            <td><span class="badge badge-${['BLOCK','BLOCKED'].includes(l.action) ? 'critical' : l.action === 'UNBLOCK' ? 'safe' : 'info'}">${l.action || '—'}</span></td>
            <td><code style="color:${['BLOCK','BLOCKED'].includes(l.action) ? 'var(--red)' : 'inherit'}">${l.ip_src || '—'}</code></td>
            <td><code>${l.ip_dst || '—'}</code></td>
            <td style="font-size:0.72rem">${l.port_dst || '—'}</td>
            <td><span class="badge badge-info">${l.protocole || '—'}</span></td>
          </tr>`).join('');
      })
      .catch(e => console.error('FW loadLogs:', e));
  }

  /* ── Actions ─────────────────────────────────────────── */
  function block(ip, raison) {
    const r = raison || prompt('Raison du blocage :', 'Blocage manuel');
    if (r === null) return;
    fetch(`/api/firewall/bloquer/${encodeURIComponent(ip)}?raison=${encodeURIComponent(r)}`)
      .then(res => res.json())
      .then(d => { Toast.show(d.message || d.msg || 'IP bloquée', 'success'); loadBlocked(); })
      .catch(() => Toast.show('Erreur blocage', 'error'));
  }

  function unblock(ip) {
    if (!confirm(`Débloquer ${ip} ?`)) return;
    fetch(`/api/firewall/debloquer/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(d => { Toast.show(d.message || d.msg || 'IP débloquée', 'success'); loadBlocked(); })
      .catch(() => Toast.show('Erreur déblocage', 'error'));
  }

  function toggleRule(ruleId, actif) {
    fetch(`/api/firewall/rules/${ruleId}/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actif }),
    })
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Règle mise à jour', 'success'); loadRules(); })
      .catch(() => Toast.show('Erreur toggle règle', 'error'));
  }

  function deleteRule(ruleId) {
    if (!confirm('Supprimer cette règle ?')) return;
    fetch(`/api/firewall/rules/${ruleId}/delete`, { method: 'DELETE' })
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Règle supprimée', 'success'); loadRules(); })
      .catch(() => Toast.show('Erreur suppression', 'error'));
  }

  function addWhitelist() {
    const ip = document.getElementById('wl-ip-input')?.value?.trim();
    if (!ip) { Toast.show('Entrez une IP', 'error'); return; }
    fetch(`/api/firewall/whitelist/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(d => {
        Toast.show(d.message || d.msg || 'IP whitelistée', 'success');
        const inp = document.getElementById('wl-ip-input');
        if (inp) inp.value = '';
        loadWhitelist();
        updateFirewallStats();
      })
      .catch(() => Toast.show('Erreur whitelist', 'error'));
  }

  function removeWhitelist(ip) {
    if (!confirm(`Retirer ${ip} de la whitelist ?`)) return;
    fetch(`/api/firewall/whitelist/${encodeURIComponent(ip)}/remove`, { method: 'DELETE' })
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Retiré', 'success'); loadWhitelist(); updateFirewallStats(); })
      .catch(() => Toast.show('Erreur', 'error'));
  }

  function addBlacklist() {
    const ip = document.getElementById('bl-ip-input')?.value?.trim();
    if (!ip) { Toast.show('Entrez une IP', 'error'); return; }
    fetch('/api/firewall/blacklist/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, raison: 'Blacklist manuelle' }),
    })
      .then(r => r.json())
      .then(d => {
        Toast.show(d.message || 'Ajouté à la blacklist', 'success');
        const inp = document.getElementById('bl-ip-input');
        if (inp) inp.value = '';
        loadBlacklist();
        updateFirewallStats();
      })
      .catch(() => Toast.show('Erreur blacklist', 'error'));
  }

  function autoResponse() {
    fetch('/api/firewall/auto-response', { method: 'POST' })
      .then(r => r.json())
      .then(d => {
        Toast.show(d.message || `${d.total || 0} actions effectuées`, 'success');
        loadBlocked();
        updateFirewallStats();
      })
      .catch(() => Toast.show('Erreur auto-response', 'error'));
  }

  function openBlockModal() {
    const ip = prompt('IP à bloquer :');
    if (!ip?.trim()) return;
    const raison = prompt('Raison :', 'Blocage manuel') || 'Blocage manuel';
    block(ip.trim(), raison);
  }

  function openRuleModal() {
    const ip     = prompt('IP source (* pour tout) :', '');
    if (ip === null) return;
    const port   = prompt('Port (vide = tout) :',         '') || null;
    const proto  = prompt('Protocole (tcp/udp/all) :',   'tcp') || 'tcp';
    const type_  = prompt('Action (BLOCK/ALLOW) :',      'BLOCK') || 'BLOCK';
    const raison = prompt('Commentaire :',                'Règle manuelle') || 'Règle manuelle';
    fetch('/api/firewall/rules/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip || '*', port, proto, type: type_, raison }),
    })
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Règle ajoutée', 'success'); loadRules(); updateFirewallStats(); })
      .catch(() => Toast.show('Erreur ajout règle', 'error'));
  }

  function init() {
    showTab('blocked');
    updateFirewallStats();
  }

  return {
    showTab, loadBlocked, loadRules, loadWhitelist, loadBlacklist,
    loadConnections, loadLogs, block, unblock, toggleRule, deleteRule,
    addWhitelist, removeWhitelist, addBlacklist, autoResponse,
    openBlockModal, openRuleModal, init,
  };
})();

/* ══════════════════════════════════════════════════════════
   IDS MODULE — Snort 3 management
   ══════════════════════════════════════════════════════════ */
const IDS = (() => {
  let allAlerts = [];

  function refresh() {
    fetch('/api/ids/alerts?limit=100')
      .then(r => r.json())
      .then(alerts => {
        allAlerts = alerts;
        renderAlerts(alerts);
        updateStats();
        loadTopIPs();
      })
      .catch(e => console.error('IDS refresh:', e));
  }

  function renderAlerts(alerts) {
    const tbody = document.getElementById('ids-alerts-tbody');
    if (!tbody) return;
    const cnt = document.getElementById('ids-count-display');
    if (cnt) cnt.textContent = `${alerts.length} alerte(s)`;

    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="11" class="no-data">
        <i class="fas fa-shield-alt" style="color:var(--green)"></i>
        Aucune alerte —
        <button onclick="IDS.importDemo()" class="card-action" style="margin-left:0.5rem">Charger alertes démo</button>
      </td></tr>`;
      return;
    }
    tbody.innerHTML = alerts.map((a, idx) => `
      <tr onclick="IDS.showDetail(${idx})" style="cursor:pointer"
        onmouseover="this.style.background='rgba(59,130,246,0.06)'"
        onmouseout="this.style.background=''">
        <td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">${(a.timestamp || '').slice(0, 19)}</td>
        <td><code style="color:var(--red)">${a.src_ip || '—'}</code></td>
        <td style="font-size:0.72rem;color:var(--muted)">${a.src_port || '—'}</td>
        <td><code>${a.dst_ip || '—'}</code></td>
        <td style="font-size:0.72rem;color:var(--muted)">${a.dst_port || '—'}</td>
        <td><span class="badge badge-info">${a.protocole || '—'}</span></td>
        <td style="font-size:0.75rem;font-weight:700;color:${a.priority === 1 ? '#ef4444' : a.priority === 2 ? '#f59e0b' : 'var(--muted)'}">P${a.priority || 3}</td>
        <td style="font-size:0.72rem;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.message || ''}">${a.message || '—'}</td>
        <td><span class="badge badge-${a.niveau === 'CRITICAL' ? 'critical' : a.niveau === 'HIGH' ? 'high' : a.niveau === 'MEDIUM' ? 'medium' : 'low'}">${a.niveau || '—'}</span></td>
        <td style="font-size:0.65rem;color:${a.action_prise === 'BLOCKED' ? 'var(--red)' : a.action_prise === 'MONITOR' ? 'var(--orange)' : 'var(--green)'}">${a.action_prise || 'LOG'}</td>
        <td onclick="event.stopPropagation()">
          <button class="action-btn red" onclick="IDS.blockIP('${a.src_ip}')" title="Bloquer IP">
            <i class="fas fa-ban"></i>
          </button>
        </td>
      </tr>`).join('');
  }

  function updateStats() {
    fetch('/api/ids/stats')
      .then(r => r.json())
      .then(s => {
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('ids-stat-critical', s.critical || 0);
        set('ids-stat-high',     s.high     || 0);
        set('ids-stat-medium',   s.medium   || 0);
        set('ids-stat-low',      s.low      || 0);
        set('ids-stat-total',    s.total    || 0);
      })
      .catch(() => {});
  }

  function loadTopIPs() {
    fetch('/api/ids/stats')
      .then(r => r.json())
      .then(s => {
        const el = document.getElementById('ids-top-ips');
        if (!el) return;
        const ips = s.top_ips || [];
        if (!ips.length) {
          el.innerHTML = '<p class="no-data">Aucun attaquant détecté</p>';
          return;
        }
        const max = ips[0]?.nb || 1;
        el.innerHTML = ips.map(ip => `
          <div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem;border-bottom:1px solid var(--border)">
            <code style="color:var(--red);min-width:130px;font-size:0.75rem">${ip.src_ip}</code>
            <div style="flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden">
              <div style="height:100%;width:${Math.round(ip.nb / max * 100)}%;background:linear-gradient(90deg,#dc2626,#ef4444);border-radius:3px"></div>
            </div>
            <span style="font-size:0.75rem;font-weight:700;color:var(--red);min-width:24px;text-align:right">${ip.nb}</span>
            <button class="action-btn red" onclick="IDS.blockIP('${ip.src_ip}')" title="Bloquer">
              <i class="fas fa-ban"></i>
            </button>
          </div>`).join('');
      })
      .catch(() => {});
  }

  function applyFilters() {
    const level  = document.getElementById('ids-filter-level')?.value || '';
    const proto  = document.getElementById('ids-filter-proto')?.value || '';
    const search = (document.getElementById('ids-search')?.value || '').toLowerCase();
    const filtered = allAlerts.filter(a => {
      if (level  && a.niveau    !== level)  return false;
      if (proto  && a.protocole !== proto)  return false;
      if (search && !(
        (a.message || '').toLowerCase().includes(search) ||
        (a.src_ip  || '').includes(search)               ||
        (a.dst_ip  || '').includes(search)
      )) return false;
      return true;
    });
    renderAlerts(filtered);
  }

  function clearFilters() {
    ['ids-filter-level', 'ids-filter-proto', 'ids-search'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    renderAlerts(allAlerts);
  }

  function showDetail(idx) {
    const a = allAlerts[idx];
    if (!a) return;
    alert(
      `🛡️ Détail Alerte Snort\n\n` +
      `Signature  : ${a.message        || '—'}\n` +
      `SID        : ${a.sid            || '—'} rev.${a.revision || '—'}\n` +
      `Source     : ${a.src_ip         || '—'}:${a.src_port || '—'}\n` +
      `Dest       : ${a.dst_ip         || '—'}:${a.dst_port || '—'}\n` +
      `Protocole  : ${a.protocole      || '—'}\n` +
      `Priorité   : P${a.priority      || '—'} — ${a.niveau || '—'}\n` +
      `Classe     : ${a.classification || '—'}\n` +
      `Action     : ${a.action_prise   || '—'}\n` +
      `Timestamp  : ${a.timestamp      || '—'}`
    );
  }

  function blockIP(ip) {
    if (!ip || ip === '—') { Toast.show('IP invalide', 'error'); return; }
    if (!confirm(`Bloquer ${ip} ?`)) return;
    fetch(`/api/firewall/bloquer/${encodeURIComponent(ip)}?raison=${encodeURIComponent('Blocage depuis IDS Snort')}`)
      .then(r => r.json())
      .then(d => {
        Toast.show(d.message || d.msg || 'IP bloquée', 'success');
        FW.loadBlocked();
        updateFirewallStats();
      })
      .catch(() => Toast.show('Erreur blocage', 'error'));
  }

  function autoBlock() {
    fetch('/api/firewall/auto-response', { method: 'POST' })
      .then(r => r.json())
      .then(d => {
        Toast.show(d.message || `${d.total || 0} actions effectuées`, 'success');
        refresh();
        FW.loadBlocked();
        updateFirewallStats();
      })
      .catch(() => Toast.show('Erreur auto-block', 'error'));
  }

  function importDemo() {
    fetch('/api/ids/inject-demo')
      .then(r => r.json())
      .then(d => {
        Toast.show(`${d.injected || 0} alertes démo chargées`, 'success');
        setTimeout(refresh, 600);
      })
      .catch(() => Toast.show('Erreur import démo', 'error'));
  }

  function startSnort() {
    fetch('/api/ids/start')
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Snort démarré', 'success'); checkSnortStatus(); })
      .catch(() => Toast.show('Erreur démarrage Snort', 'error'));
  }

  function stopSnort() {
    if (!confirm('Arrêter Snort IDS ?')) return;
    fetch('/api/ids/stop')
      .then(r => r.json())
      .then(d => { Toast.show(d.message || 'Snort arrêté', 'info'); checkSnortStatus(); })
      .catch(() => Toast.show('Erreur', 'error'));
  }

  function checkSnortStatus() {
    fetch('/api/ids/status')
      .then(r => r.json())
      .then(s => {
        const dot  = document.getElementById('snort-status-dot');
        const text = document.getElementById('snort-status-text');
        if (dot)  dot.style.color  = s.running ? 'var(--green)' : 'var(--muted)';
        if (text) text.textContent = s.running
          ? `✅ Actif — ${s.version || 'Snort 3'}`
          : '⚪ Inactif (mode démo actif)';
      })
      .catch(() => {});
  }

  function reloadRules() {
    const el = document.getElementById('ids-rules-list');
    if (!el) return;
    el.innerHTML = '<p style="color:var(--muted)">Chargement des règles...</p>';
    fetch('/api/ids/rules')
      .then(r => r.json())
      .then(rules => {
        if (!rules.length) {
          el.innerHTML = '<p style="color:var(--muted)">Aucune règle trouvée dans /etc/snort/rules/local.rules</p>';
          return;
        }
        el.innerHTML = rules.map(r => {
          const line = r.rule || '';
          const colored = line
            .replace(/^(alert|drop|reject|pass)/, '<span style="color:#f59e0b">$1</span>')
            .replace(/(msg:"[^"]*")/g,            '<span style="color:#10b981">$1</span>')
            .replace(/(sid:\d+)/g,                '<span style="color:#3b82f6">$1</span>');
          return `<div style="padding:0.2rem 0;border-bottom:1px solid #1a2a3a;line-height:1.5;font-size:0.68rem">${colored}</div>`;
        }).join('');
        Toast.show('Règles rechargées', 'success');
      })
      .catch(() => {
        el.innerHTML = '<p style="color:var(--red)">Erreur lecture des règles Snort</p>';
      });
  }

  function init() {
    checkSnortStatus();
    refresh();
    setInterval(refresh,          30000);
    setInterval(checkSnortStatus, 15000);
  }

  return {
    refresh, renderAlerts, applyFilters, clearFilters,
    showDetail, blockIP, autoBlock, importDemo,
    startSnort, stopSnort, checkSnortStatus, reloadRules,
    loadTopIPs, updateStats, init,
  };
})();

/* ══ ACTIONS GLOBALES (compat onclick dans HTML) ═════════ */
const Actions = {
  bloquer(ip) {
    if (!confirm(`Bloquer ${ip} ?`)) return;
    fetch(`/api/firewall/bloquer/${encodeURIComponent(ip)}?raison=${encodeURIComponent('Blocage dashboard')}`)
      .then(r => r.json())
      .then(d => { Toast.show(d.msg || d.message || 'IP bloquée', 'success'); updateFirewallStats(); })
      .catch(() => Toast.show('Erreur blocage', 'error'));
  },
  debloquer(ip) {
    if (!confirm(`Débloquer ${ip} ?`)) return;
    fetch(`/api/firewall/debloquer/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(d => { Toast.show(d.msg || d.message || 'IP débloquée', 'success'); updateFirewallStats(); })
      .catch(() => Toast.show('Erreur déblocage', 'error'));
  },
  whitelist(ip) {
    if (!confirm(`Whitelister ${ip} ?`)) return;
    fetch(`/api/firewall/whitelist/${encodeURIComponent(ip)}`)
      .then(r => r.json())
      .then(d => Toast.show(d.msg || d.message || 'IP whitelistée', 'success'))
      .catch(() => Toast.show('Erreur whitelist', 'error'));
  },
  scan() {
    const btn = document.getElementById('btn-scan');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scan...'; }
    fetch('/lancer-scan')
      .then(r => r.json())
      .then(() => {
        Toast.show('Scan lancé...', 'info');
        const iv = setInterval(() => {
          fetch('/api/scan-status')
            .then(r => r.json())
            .then(s => {
              if (!s.actif) {
                clearInterval(iv);
                if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-search"></i> Scanner'; }
                Toast.show('Scan terminé !', 'success');
                setTimeout(() => location.reload(), 1200);
              }
            });
        }, 5000);
      })
      .catch(() => {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-search"></i> Scanner'; }
        Toast.show('Erreur scan', 'error');
      });
  },
  traiterSuricata() {
    fetch('/api/firewall/traiter-suricata', { method: 'POST' })
      .then(r => r.json())
      .then(d => {
        Toast.show(`${d.total || 0} actions effectuées`, 'success');
        updateFirewallStats();
        FW.loadBlocked();
      })
      .catch(() => Toast.show('Erreur', 'error'));
  },
  importerSuricata() {
    fetch('/suricata/importer')
      .then(r => r.json())
      .then(d => { Toast.show(`${d.imported || 0} alertes importées`, 'success'); IDS.refresh(); })
      .catch(() => Toast.show('Erreur import', 'error'));
  },
};

/* ══ CLAVIER + INIT ══════════════════════════════════════ */
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'k') {
    e.preventDefault();
    document.getElementById('search-input')?.focus();
  }
  if (e.key === 'Escape') Help.close();
});

document.addEventListener('DOMContentLoaded', () => {
  // Init thème
  Theme.init();
  initTopbarDate();

  // Chargement initial des données communes
  loadInsights();
  updateFirewallStats();
  loadIncidents();
  loadThreatIntel();
  loadAssets();
  loadMitre();

  // Enregistrement lazy loaders par onglet
  Nav.register('firewall',           () => FW.init());
  Nav.register('alerts',             () => IDS.init());
  Nav.register('timeline',           loadTimeline);
  Nav.register('ai-page',            loadAISysResume);
  Nav.register('monitoring',         updateMonitoring);
  Nav.register('smart-correlations', loadCorrelations);
  Nav.register('network-topology',   initTopology);
  Nav.register('soc-terminal',       () => Terminal.start());
  Nav.register('reports',            loadReports);
  Nav.register('incidents',          loadIncidents);
  Nav.register('threat-intel',       loadThreatIntel);
  Nav.register('assets',             loadAssets);
  Nav.register('mitre',              loadMitre);

  // Auto-refresh périodique
  setInterval(updateFirewallStats, 20000);
  setInterval(updateMonitoring,    12000);
  setInterval(loadInsights,        60000);

  // Fermeture help modal au clic extérieur
  document.getElementById('help-modal')?.addEventListener('click', function(e) {
    if (e.target === this) Help.close();
  });

  // Démarrer le terminal SOC
  Terminal.start();

  // Premier cycle monitoring
  updateMonitoring();
});

/* ══ EXPOSITION GLOBALE ══════════════════════════════════ */
window.toggleTheme      = () => Theme.toggle();
window.showPage         = (n, e) => Nav.show(n, e);
window.handleSearch     = v => Search.handle(v);
window.toggleHelp       = () => Help.toggle();
window.toggleAI         = () => { if (window.AI) AI.toggle(); };
window.helpSearch       = helpSearch;
window.helpGoTo         = helpGoTo;

// Firewall actions (compat onclick dans HTML Jinja)
window.bloquerIP        = ip => Actions.bloquer(ip);
window.debloquerIP      = ip => Actions.debloquer(ip);
window.whitelistIP      = ip => Actions.whitelist(ip);
window.lancerScan       = () => Actions.scan();
window.traiterSuricata  = () => Actions.traiterSuricata();
window.importerSuricata = () => Actions.importerSuricata();

// Reports
window.generateReport   = generateReport;
window.filterReports    = filterReports;
window.loadReports      = loadReports;

// Modules exposés
window.FW       = FW;
window.IDS      = IDS;
window.Toast    = Toast;
window.Terminal = Terminal;
window.Theme    = Theme;
window.Nav      = Nav;
