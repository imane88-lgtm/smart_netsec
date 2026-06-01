/* ══════════════════════════════════════════════════════════
   firewall.js — Professional nftables Management Console
   Injected/loaded when the Firewall tab is active.
   All functions exposed on window.FW (already in app.js).
   This file adds the HTML panel builder.
   ══════════════════════════════════════════════════════════ */
'use strict';

/* ── Build Firewall Tab HTML ─────────────────────────────── */
function buildFirewallPanel() {
  const container = document.getElementById('fw-main-container');
  if (!container || container.dataset.built) return;
  container.dataset.built = '1';
  container.innerHTML = `
<!-- KPI Row -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.75rem;margin-bottom:1rem">
  ${[
    ['fw-blocked',      'fa-ban',           'red',    'IPs Bloquées'],
    ['fw-wl',           'fa-check-circle',  'green',  'Whitelist'],
    ['fw-bl',           'fa-skull-crossbones','orange','Blacklist'],
    ['fw-rules-count',  'fa-list-alt',      'blue',   'Règles Actives'],
  ].map(([id, icon, col, label]) => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);padding:0.85rem;display:flex;align-items:center;gap:0.75rem">
      <div style="width:36px;height:36px;border-radius:var(--radius-sm);background:var(--${col})14;color:var(--${col});display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">
        <i class="fas ${icon}"></i>
      </div>
      <div>
        <div id="${id}" style="font-size:1.4rem;font-weight:800;color:var(--${col})">0</div>
        <div style="font-size:0.62rem;color:var(--muted);text-transform:uppercase;font-weight:600">${label}</div>
      </div>
    </div>`).join('')}
</div>

<!-- Tab bar -->
<div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:0.85rem;background:var(--card);border-radius:var(--radius-sm) var(--radius-sm) 0 0;overflow:hidden">
  ${[
    ['blocked',     'fa-ban',           'IPs Bloquées'],
    ['rules',       'fa-list-alt',      'Règles nftables'],
    ['whitelist',   'fa-check-circle',  'Whitelist'],
    ['blacklist',   'fa-skull-crossbones','Blacklist'],
    ['connections', 'fa-network-wired', 'Live Connexions'],
    ['logs',        'fa-file-alt',      'Logs FW'],
  ].map(([tab, icon, label]) => `
    <button id="fw-tab-${tab}" class="fw-tab-btn" onclick="FW.showTab('${tab}')"
      style="padding:0.6rem 0.9rem;background:none;border:none;border-bottom:2px solid transparent;
             cursor:pointer;font-size:0.72rem;font-weight:600;color:var(--muted);
             display:flex;align-items:center;gap:0.35rem;transition:all .2s;white-space:nowrap">
      <i class="fas ${icon}"></i> ${label}
    </button>`).join('')}
  <!-- Actions rapides -->
  <div style="margin-left:auto;display:flex;gap:0.5rem;align-items:center;padding:0 0.75rem">
    <button class="card-action" onclick="FW.openBlockModal()" title="Bloquer une IP">
      <i class="fas fa-plus"></i> Bloquer IP
    </button>
    <button class="card-action" onclick="FW.openRuleModal()" title="Nouvelle règle nftables">
      <i class="fas fa-plus"></i> Règle
    </button>
    <button class="card-action" onclick="FW.autoResponse()" title="Auto-réponse IDS">
      <i class="fas fa-robot"></i> Auto-Response
    </button>
  </div>
</div>

<!-- ══ PANEL: IPs Bloquées ══ -->
<div id="fw-panel-blocked" class="fw-panel">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">IPs actuellement bloquées par nftables</span>
    <button class="card-action" onclick="FW.loadBlocked()"><i class="fas fa-sync"></i> Refresh</button>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr>
        <th>IP Source</th><th>Raison</th><th>Niveau</th>
        <th>Type</th><th>Date blocage</th><th>Action</th>
      </tr></thead>
      <tbody id="fw-blocked-tbody">
        <tr><td colspan="6" class="no-data"><i class="fas fa-spinner fa-spin"></i> Chargement...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ══ PANEL: Règles nftables ══ -->
<div id="fw-panel-rules" class="fw-panel" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">Règles nftables persistées</span>
    <div style="display:flex;gap:0.5rem">
      <button class="card-action" onclick="FW.loadRules()"><i class="fas fa-sync"></i> Refresh</button>
      <button class="card-action green" onclick="FW.openRuleModal()"><i class="fas fa-plus"></i> Nouvelle règle</button>
    </div>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr>
        <th>ID</th><th>Action</th><th>IP Source</th><th>Port</th>
        <th>Proto</th><th>Direction</th><th>Priorité</th>
        <th>Statut</th><th>Créée</th><th>Actions</th>
      </tr></thead>
      <tbody id="fw-rules-tbody">
        <tr><td colspan="10" class="no-data">Chargement...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ══ PANEL: Whitelist ══ -->
<div id="fw-panel-whitelist" class="fw-panel" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">IPs toujours autorisées</span>
    <div style="display:flex;gap:0.5rem;align-items:center">
      <input id="wl-ip-input" type="text" placeholder="192.168.1.x ou CIDR"
        style="padding:0.35rem 0.6rem;background:var(--input);border:1px solid var(--border);
               border-radius:var(--radius-sm);color:var(--text);font-size:0.75rem;width:180px"
        onkeypress="if(event.key==='Enter') FW.addWhitelist()">
      <button class="card-action green" onclick="FW.addWhitelist()"><i class="fas fa-plus"></i> Ajouter</button>
      <button class="card-action" onclick="FW.loadWhitelist()"><i class="fas fa-sync"></i></button>
    </div>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr><th>IP</th><th>Raison</th><th>Date ajout</th><th>Action</th></tr></thead>
      <tbody id="fw-wl-tbody">
        <tr><td colspan="4" class="no-data">Chargement...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ══ PANEL: Blacklist ══ -->
<div id="fw-panel-blacklist" class="fw-panel" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">IPs malveillantes connues</span>
    <div style="display:flex;gap:0.5rem;align-items:center">
      <input id="bl-ip-input" type="text" placeholder="IP malveillante"
        style="padding:0.35rem 0.6rem;background:var(--input);border:1px solid var(--border);
               border-radius:var(--radius-sm);color:var(--text);font-size:0.75rem;width:180px"
        onkeypress="if(event.key==='Enter') FW.addBlacklist()">
      <button class="card-action red" onclick="FW.addBlacklist()"><i class="fas fa-plus"></i> Blacklister</button>
      <button class="card-action" onclick="FW.loadBlacklist()"><i class="fas fa-sync"></i></button>
    </div>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr><th>IP</th><th>Raison</th><th>Source</th><th>Date</th><th>Action</th></tr></thead>
      <tbody id="fw-bl-tbody">
        <tr><td colspan="5" class="no-data">Chargement...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ══ PANEL: Live Connexions ══ -->
<div id="fw-panel-connections" class="fw-panel" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">Connexions réseau actives (/proc/net)</span>
    <button class="card-action" onclick="FW.loadConnections()"><i class="fas fa-sync"></i> Refresh</button>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr>
        <th>Proto</th><th>État</th><th>IP Locale</th><th>Port L.</th>
        <th>IP Distante</th><th>Port D.</th><th>Process</th><th>Statut</th>
      </tr></thead>
      <tbody id="fw-conn-tbody">
        <tr><td colspan="8" class="no-data">Cliquez Refresh pour charger</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ══ PANEL: Logs FW ══ -->
<div id="fw-panel-logs" class="fw-panel" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem">
    <span style="font-size:0.72rem;font-weight:700;color:var(--muted)">Journal des actions firewall</span>
    <button class="card-action" onclick="FW.loadLogs()"><i class="fas fa-sync"></i> Refresh</button>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table" style="width:100%">
      <thead><tr>
        <th>Timestamp</th><th>Action</th><th>IP Source</th>
        <th>IP Dest</th><th>Port</th><th>Protocole</th>
      </tr></thead>
      <tbody id="fw-logs-tbody">
        <tr><td colspan="6" class="no-data">Chargement...</td></tr>
      </tbody>
    </table>
  </div>
</div>
`;
}

/* ── Auto-build on DOMContentLoaded ─────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  buildFirewallPanel();
});

window.buildFirewallPanel = buildFirewallPanel;
