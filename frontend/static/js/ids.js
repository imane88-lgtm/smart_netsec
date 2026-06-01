/* ══════════════════════════════════════════════════════════
   ids.js — Professional Snort IDS Management Panel
   Builds the Alerts/IDS tab HTML and wires all actions.
   ══════════════════════════════════════════════════════════ */
'use strict';

function buildIDSPanel() {
  const container = document.getElementById('ids-main-container');
  if (!container || container.dataset.built) return;
  container.dataset.built = '1';
  container.innerHTML = `
<!-- Status bar -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem">
  <div style="display:flex;align-items:center;gap:0.75rem">
    <i id="snort-status-dot" class="fas fa-circle" style="color:var(--muted);font-size:0.65rem"></i>
    <span id="snort-status-text" style="font-size:0.78rem;font-weight:600">Vérification Snort...</span>
  </div>
  <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
    <button class="card-action green" onclick="IDS.startSnort()"><i class="fas fa-play"></i> Démarrer</button>
    <button class="card-action red"   onclick="IDS.stopSnort()"><i class="fas fa-stop"></i> Arrêter</button>
    <button class="card-action"       onclick="IDS.refresh()"><i class="fas fa-sync"></i> Refresh</button>
    <button class="card-action orange" onclick="IDS.autoBlock()"><i class="fas fa-robot"></i> Auto-Block</button>
    <button class="card-action"       onclick="IDS.importDemo()"><i class="fas fa-upload"></i> Démo</button>
  </div>
</div>

<!-- KPI Stats -->
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:0.6rem;margin-bottom:1rem">
  ${[
    ['ids-stat-total',    'fa-shield-alt',     'blue',   'Total'],
    ['ids-stat-critical', 'fa-skull',          'red',    'Critical'],
    ['ids-stat-high',     'fa-exclamation-triangle','orange','High'],
    ['ids-stat-medium',   'fa-exclamation-circle','yellow','Medium'],
    ['ids-stat-low',      'fa-info-circle',    'muted',  'Low'],
  ].map(([id, icon, col, label]) => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:0.65rem;text-align:center">
      <div style="font-size:1.2rem;font-weight:800;color:var(--${col})" id="${id}">0</div>
      <div style="font-size:0.6rem;color:var(--muted);text-transform:uppercase;font-weight:700">${label}</div>
    </div>`).join('')}
</div>

<!-- Two-column layout: alerts + right panel -->
<div style="display:grid;grid-template-columns:1fr 260px;gap:0.85rem;align-items:start">

  <!-- Alert Stream -->
  <div>
    <!-- Filtres -->
    <div style="display:flex;gap:0.5rem;margin-bottom:0.6rem;flex-wrap:wrap;align-items:center">
      <input id="ids-search" type="text" placeholder="🔍 IP, message, SID..."
        style="padding:0.3rem 0.6rem;background:var(--input);border:1px solid var(--border);
               border-radius:var(--radius-sm);color:var(--text);font-size:0.72rem;flex:1;min-width:160px"
        oninput="IDS.applyFilters()">
      <select id="ids-filter-level" onchange="IDS.applyFilters()"
        style="padding:0.3rem 0.5rem;background:var(--input);border:1px solid var(--border);
               border-radius:var(--radius-sm);color:var(--text);font-size:0.72rem">
        <option value="">Tous niveaux</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
      <select id="ids-filter-proto" onchange="IDS.applyFilters()"
        style="padding:0.3rem 0.5rem;background:var(--input);border:1px solid var(--border);
               border-radius:var(--radius-sm);color:var(--text);font-size:0.72rem">
        <option value="">Tous proto</option>
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
        <option value="ICMP">ICMP</option>
      </select>
      <button class="card-action" onclick="IDS.clearFilters()"><i class="fas fa-times"></i></button>
      <span id="ids-count-display" style="font-size:0.68rem;color:var(--muted);margin-left:auto"></span>
    </div>

    <!-- Table alertes -->
    <div style="overflow-x:auto">
      <table class="data-table" style="width:100%;min-width:780px">
        <thead><tr>
          <th>Timestamp</th><th>Src IP</th><th>Src Port</th>
          <th>Dst IP</th><th>Dst Port</th><th>Proto</th>
          <th>Prio</th><th>Signature</th><th>Niveau</th>
          <th>Action</th><th style="width:40px"></th>
        </tr></thead>
        <tbody id="ids-alerts-tbody">
          <tr><td colspan="11" class="no-data">
            <i class="fas fa-spinner fa-spin"></i> Chargement alertes...
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Right panel -->
  <div style="display:flex;flex-direction:column;gap:0.85rem">

    <!-- Top attaquants -->
    <div class="card" style="padding:0.85rem">
      <div class="card-header" style="margin-bottom:0.6rem">
        <span class="card-title"><i class="fas fa-crosshairs" style="color:var(--red)"></i> Top Attaquants</span>
      </div>
      <div id="ids-top-ips" style="font-size:0.72rem">
        <p class="no-data">Chargement...</p>
      </div>
    </div>

    <!-- Règles Snort -->
    <div class="card" style="padding:0.85rem">
      <div class="card-header" style="margin-bottom:0.6rem;display:flex;justify-content:space-between;align-items:center">
        <span class="card-title"><i class="fas fa-scroll" style="color:var(--orange)"></i> Règles Snort</span>
        <button class="card-action" onclick="IDS.reloadRules()" style="font-size:0.62rem">
          <i class="fas fa-sync"></i>
        </button>
      </div>
      <div id="ids-rules-list"
        style="font-family:monospace;font-size:0.62rem;max-height:220px;overflow-y:auto;
               background:var(--card2);border-radius:var(--radius-sm);padding:0.5rem;
               color:var(--text);line-height:1.6">
        <p style="color:var(--muted)">Cliquez 🔄 pour lire local.rules</p>
      </div>
    </div>

    <!-- Classification chart texte -->
    <div class="card" style="padding:0.85rem">
      <div class="card-title" style="margin-bottom:0.5rem">
        <i class="fas fa-chart-pie" style="color:var(--purple)"></i> Répartition
      </div>
      <div id="ids-distrib" style="font-size:0.72rem">
        ${[
          ['CRITICAL', '#ef4444'], ['HIGH','#f59e0b'],
          ['MEDIUM','#ca8a04'],    ['LOW','#3b82f6'],
        ].map(([lvl, col]) => `
          <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.35rem">
            <span style="width:8px;height:8px;border-radius:50%;background:${col};flex-shrink:0"></span>
            <span style="color:var(--muted);flex:1;font-size:0.68rem">${lvl}</span>
            <span id="ids-pct-${lvl.toLowerCase()}" style="font-weight:700;color:${col}">—</span>
          </div>`).join('')}
      </div>
    </div>
  </div>
</div>
`;

  // Mettre à jour les pourcentages une fois les stats chargées
  _patchDistribUpdate();
}

function _patchDistribUpdate() {
  const orig = window.IDS?.updateStats;
  if (!orig) return;
  const patched = function () {
    orig.call(window.IDS);
    fetch('/api/ids/stats')
      .then(r => r.json())
      .then(s => {
        const total = s.total || 1;
        ['critical', 'high', 'medium', 'low'].forEach(lvl => {
          const el = document.getElementById('ids-pct-' + lvl);
          if (el) el.textContent = Math.round((s[lvl] || 0) / total * 100) + '%';
        });
      })
      .catch(() => {});
  };
  if (window.IDS) window.IDS.updateStats = patched;
}

document.addEventListener('DOMContentLoaded', () => {
  buildIDSPanel();
});

window.buildIDSPanel = buildIDSPanel;
