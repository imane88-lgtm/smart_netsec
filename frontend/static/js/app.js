/* ══════════════════════════════════════════════════════════
   app.js — Smart NetSec SOC v3.0
   Version: COMPLETE FINAL
   Tous les modules sont ici, tous les boutons fonctionnent.
══════════════════════════════════════════════════════════ */
'use strict';

/* ══════════════════════════════════════════════
   UTILITAIRES GLOBAUX
══════════════════════════════════════════════ */

// Helper fetch avec credentials
function apiFetch(url, opts) {
  opts = opts || {};
  opts.credentials = 'same-origin';
  return fetch(url, opts).then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + url);
    return r.json();
  });
}

function apiPost(url, body) {
  return apiFetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {})
  });
}

// Toast notifications
var Toast = {
  show: function(msg, type, dur) {
    type = type || 'info'; dur = dur || 3500;
    var colors = {success:'#10b981',error:'#ef4444',info:'#3b82f6',warn:'#f59e0b'};
    var icons  = {success:'fa-check-circle',error:'fa-exclamation-circle',
                  info:'fa-info-circle',warn:'fa-exclamation-triangle'};
    var t = document.createElement('div');
    t.style.cssText = [
      'position:fixed;bottom:1.5rem;right:1.5rem;z-index:99999',
      'background:var(--card,#1e2d45);border-radius:8px;padding:0.7rem 1rem',
      'font-size:0.78rem;box-shadow:0 4px 20px rgba(0,0,0,0.3)',
      'display:flex;align-items:center;gap:0.5rem;min-width:220px;max-width:360px',
      'border-left:3px solid ' + (colors[type]||colors.info),
      'animation:slideInRight 0.3s ease'
    ].join(';');
    t.innerHTML = '<i class="fas ' + (icons[type]||icons.info) +
      '" style="color:' + (colors[type]||colors.info) + '"></i><span style="color:var(--text,#e2e8f0)">' +
      msg + '</span>';
    document.body.appendChild(t);
    setTimeout(function() { t.style.opacity='0'; t.style.transition='opacity 0.3s';
      setTimeout(function(){t.remove();},300); }, dur);
  }
};

/* ══════════════════════════════════════════════
   THÈME
══════════════════════════════════════════════ */
var Theme = {
  get: function() { return localStorage.getItem('netsec-theme') || 'dark'; },
  set: function(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('netsec-theme', t);
    var icon = document.getElementById('theme-icon');
    if (icon) icon.className = t === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
  },
  toggle: function() { this.set(this.get() === 'dark' ? 'light' : 'dark'); },
  init: function() { this.set(this.get()); }
};

/* ══════════════════════════════════════════════
   NAVIGATION SPA
══════════════════════════════════════════════ */
var Nav = {
  _loaders: {},
  _current: null,
  show: function(name, el) {
    // Cacher toutes les pages
    document.querySelectorAll('.page').forEach(function(p) {
      p.classList.remove('active');
    });
    // Désactiver tous les nav items
    document.querySelectorAll('.nav-item').forEach(function(n) {
      n.classList.remove('active');
    });
    // Activer la page demandée
    var page = document.getElementById('page-' + name);
    if (!page) { console.warn('Page non trouvée: page-' + name); return; }
    page.classList.add('active');
    // Activer le nav item
    if (el) {
      el.classList.add('active');
    } else {
      var navEl = document.getElementById('nav-' + name);
      if (navEl) navEl.classList.add('active');
    }
    this._current = name;
    // Appeler le loader si enregistré
    if (this._loaders[name]) {
      try { this._loaders[name](); } catch(e) { console.error('Loader error ['+name+']:', e); }
    }
  },
  register: function(name, fn) { this._loaders[name] = fn; }
};

/* ══════════════════════════════════════════════
   RECHERCHE TOPBAR
══════════════════════════════════════════════ */
var Search = {
  map: {
    'overview':'dashboard','dashboard':'dashboard',
    'device':'devices','appareil':'devices',
    'alert':'alerts','alerte':'alerts','ids':'alerts','snort':'alerts',
    'fire':'firewall','bloc':'firewall','nft':'firewall',
    'whitelist':'firewall','blacklist':'firewall',
    'monitor':'monitoring','cpu':'monitoring','ram':'monitoring',
    'report':'reports','rapport':'reports',
    'ai':'ai-page','assist':'ai-page',
    'time':'timeline',
    'network':'network-topology','map':'network-topology',
    'incident':'incidents',
    'threat':'threat-intel','intel':'threat-intel',
    'mitre':'mitre',
    'asset':'assets',
    'terminal':'soc-terminal',
    'correl':'smart-correlations',
  },
  handle: function(val) {
    val = (val||'').toLowerCase().trim();
    if (!val) return;
    for (var kw in this.map) {
      if (val.indexOf(kw) >= 0) { Nav.show(this.map[kw]); return; }
    }
  }
};

/* ══════════════════════════════════════════════
   HELP MODAL
══════════════════════════════════════════════ */
var Help = {
  toggle: function() {
    var m = document.getElementById('help-modal');
    if (m) m.classList.toggle('open');
  },
  close: function() {
    var m = document.getElementById('help-modal');
    if (m) m.classList.remove('open');
  }
};

function helpSearch(q) {
  q = (q||'').toLowerCase();
  document.querySelectorAll('.help-section').forEach(function(s) {
    s.style.display = (!q || s.textContent.toLowerCase().indexOf(q)>=0) ? '' : 'none';
  });
}

function helpGoTo(id) {
  var el = document.getElementById('help-'+id);
  if (el) el.scrollIntoView({behavior:'smooth',block:'center'});
}

/* ══════════════════════════════════════════════
   DATE TOPBAR
══════════════════════════════════════════════ */
function initTopbarDate() {
  var el = document.getElementById('topbar-date');
  if (!el) return;
  var now  = new Date();
  var prev = new Date(now - 7*86400000);
  var fmt  = function(d) {
    return d.toLocaleDateString('fr-FR',{day:'2-digit',month:'short',year:'numeric'});
  };
  el.textContent = fmt(prev) + ' – ' + fmt(now);
}

/* ══════════════════════════════════════════════
   KPI FIREWALL (topbar)
══════════════════════════════════════════════ */
function updateFirewallStats() {
  apiFetch('/api/firewall/stats')
    .then(function(d) {
      var set = function(id,v) { var e=document.getElementById(id); if(e) e.textContent=v; };
      set('fw-blocked',     d.nb_bloques   || 0);
      set('fw-wl',          d.nb_whitelist || 0);
      set('fw-bl',          d.nb_blacklist || 0);
      set('fw-rules-count', d.nb_rules     || 0);
      set('kpi-blocked',    d.nb_bloques   || 0);
    })
    .catch(function(e) { console.warn('FW stats:', e.message); });
}

/* ══════════════════════════════════════════════
   INSIGHTS
══════════════════════════════════════════════ */
function loadInsights() {
  apiFetch('/api/intelligence/recommandations')
    .then(function(data) {
      var def = ['Système surveillé','Aucune anomalie critique','Scan régulier recommandé'];
      ['ins-1','ins-2','ins-3'].forEach(function(id,i) {
        var el = document.getElementById(id);
        if (el) el.textContent = (data[i]&&(data[i].description||data[i].titre)) || def[i];
      });
    })
    .catch(function() {});
}

/* ══════════════════════════════════════════════
   TIMELINE
══════════════════════════════════════════════ */
function loadTimeline() {
  var el = document.getElementById('timeline-list');
  if (!el) return;
  el.innerHTML = '<p class="no-data"><i class="fas fa-spinner fa-spin"></i> Chargement...</p>';
  apiFetch('/api/intelligence/timeline')
    .then(function(data) {
      if (!data.length) {
        el.innerHTML = '<p class="no-data"><i class="fas fa-inbox"></i> Aucun événement</p>';
        return;
      }
      var colors = {CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#ca8a04',LOW:'#3b82f6'};
      var icons  = {ALERTE:'fa-bell',IDS:'fa-shield-virus',
                    FIREWALL:'fa-fire-alt',CORRELATION:'fa-project-diagram'};
      el.innerHTML = data.map(function(t) {
        var col  = colors[t.niveau]  || '#3b82f6';
        var icon = icons[t.type_ev]  || 'fa-circle';
        return '<div style="display:flex;gap:0.9rem;padding:0.65rem 0.5rem;' +
          'border-bottom:1px solid var(--border);align-items:flex-start">' +
          '<div style="width:28px;height:28px;border-radius:50%;background:'+col+'14;' +
          'border:1.5px solid '+col+';display:flex;align-items:center;justify-content:center;' +
          'font-size:0.68rem;color:'+col+';flex-shrink:0">' +
          '<i class="fas '+icon+'"></i></div>' +
          '<div style="flex:1;min-width:0">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:0.12rem">' +
          '<span style="font-size:0.7rem;font-weight:700;color:var(--blue)">'+(t.type_ev||'—')+'</span>' +
          '<span style="font-size:0.63rem;color:var(--muted)">'+(t.ts||'').slice(0,19)+'</span></div>' +
          '<code>'+(t.ip||'—')+'</code>' +
          '<div style="font-size:0.68rem;color:var(--muted);overflow:hidden;' +
          'text-overflow:ellipsis;white-space:nowrap;max-width:360px;margin-top:0.1rem">' +
          (t.message||'—')+'</div></div>' +
          '<span style="font-size:0.6rem;font-weight:700;padding:0.15rem 0.45rem;' +
          'border-radius:20px;background:'+col+'14;color:'+col+';border:1px solid '+col+'25">' +
          (t.niveau||'—')+'</span></div>';
      }).join('');
    })
    .catch(function(e) {
      el.innerHTML = '<p class="no-data" style="color:var(--red)">Erreur: '+e.message+'</p>';
    });
}

/* ══════════════════════════════════════════════
   CORRÉLATIONS
══════════════════════════════════════════════ */
function loadCorrelations() {
  var el = document.getElementById('correlation-list');
  if (!el) return;
  el.innerHTML = '<p class="no-data"><i class="fas fa-spinner fa-spin"></i> Chargement...</p>';
  apiFetch('/api/intelligence/correlations')
    .then(function(data) {
      if (!data.length) {
        el.innerHTML = '<p class="no-data"><i class="fas fa-check-circle" style="color:var(--green)"></i> Aucune corrélation</p>';
        return;
      }
      el.innerHTML = data.map(function(e) {
        var col = e.severite==='CRITICAL'?'var(--red)':'var(--orange)';
        return '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.6rem 0.85rem;' +
          'border-radius:var(--radius-sm);margin-bottom:0.35rem;background:var(--card2);' +
          'border:1px solid var(--border);border-left:2px solid '+col+'">' +
          '<i class="fas fa-project-diagram" style="color:'+col+'"></i>' +
          '<div style="flex:1;min-width:0">' +
          '<div style="font-size:0.75rem;font-weight:600">'+(e.rule_nom||'—')+'</div>' +
          '<div style="font-size:0.65rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis">' +
          (e.explication||'—')+'</div></div>' +
          '<code>'+(e.ip||'—')+'</code>' +
          '<span class="badge badge-'+(e.severite==='CRITICAL'?'critical':'high')+'">' +
          (e.severite||'—')+'</span></div>';
      }).join('');
    })
    .catch(function(e) {
      el.innerHTML = '<p class="no-data" style="color:var(--red)">Erreur: '+e.message+'</p>';
    });
}

/* ══════════════════════════════════════════════
   AI PAGE RESUME
══════════════════════════════════════════════ */
function loadAISysResume() {
  apiFetch('/ai/resume')
    .then(function(d) {
      var el = document.getElementById('ai-sys-resume');
      if (!el) return;
      var sc  = d.score||0;
      var col = sc>=80?'#10b981':sc>=60?'#f59e0b':'#ef4444';
      var lbl = sc>=80?'SAFE':sc>=60?'WARNING':'DANGER';
      el.innerHTML = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.6rem;margin-bottom:0.8rem">' +
        [[sc+'/100','Score',col],[d.nb_appareils||0,'Devices','var(--blue)'],
         [d.nb_critical||0,'Critiques','var(--red)'],[d.nb_bloques||0,'Bloquées','var(--orange)']
        ].map(function(v) {
          return '<div style="background:var(--card2);border:1px solid var(--border);' +
            'border-radius:var(--radius-sm);padding:0.6rem;text-align:center">' +
            '<div style="font-size:1.2rem;font-weight:800;color:'+v[2]+'">' +v[0]+'</div>' +
            '<div style="font-size:0.6rem;color:var(--muted);text-transform:uppercase">' +v[1]+'</div></div>';
        }).join('') + '</div>' +
        '<div style="background:rgba(0,0,0,0.1);border-radius:var(--radius-sm);padding:0.6rem;' +
        'text-align:center;font-size:0.78rem;font-weight:700;color:'+col+'">Statut : '+lbl+'</div>';
    })
    .catch(function() {});
}

/* ══════════════════════════════════════════════
   REPORTS
══════════════════════════════════════════════ */
function loadReports() {
  var tbody = document.getElementById('reports-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="no-data"><i class="fas fa-spinner fa-spin"></i></td></tr>';
  apiFetch('/api/rapports')
    .then(function(rapports) {
      if (!rapports.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">Aucun rapport — générez-en un</td></tr>';
        return;
      }
      tbody.innerHTML = rapports.map(function(r) {
        var sc = r.score_global||0;
        var bc = sc>=80?'badge-safe':sc>=60?'badge-medium':'badge-critical';
        return '<tr class="report-row" data-date="'+(r.date_creation||'')+'">' +
          '<td style="color:var(--muted);font-weight:600">#'+r.id+'</td>' +
          '<td style="font-size:0.72rem;white-space:nowrap">'+(r.date_creation||'').slice(0,19)+'</td>' +
          '<td style="font-size:0.78rem">'+(r.titre||'Rapport SOC')+'</td>' +
          '<td><span class="badge badge-info">'+(r.nb_appareils||0)+'</span></td>' +
          '<td><span class="badge '+bc+'">'+sc+'/100</span></td>' +
          '<td><a href="/generer-rapport" target="_blank" class="action-btn green" title="PDF">' +
          '<i class="fas fa-file-pdf"></i></a></td></tr>';
      }).join('');
    })
    .catch(function(e) {
      tbody.innerHTML = '<tr><td colspan="6" class="no-data" style="color:var(--red)">Erreur: '+e.message+'</td></tr>';
    });
}

function generateReport() {
  var btn = document.getElementById('btn-gen-report');
  if (btn) { btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; }
  window.open('/generer-rapport','_blank');
  setTimeout(function() {
    loadReports();
    if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-plus"></i> Nouveau rapport'; }
    Toast.show('Rapport généré !','success');
  }, 2500);
}

function filterReports(type, btn) {
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});
  if (btn) btn.classList.add('active');
  var now = Date.now();
  document.querySelectorAll('.report-row').forEach(function(row) {
    if (type==='all') { row.style.display=''; return; }
    var d = new Date(row.dataset.date);
    row.style.display = (!isNaN(d) && now-d < 7*86400000) ? '' : 'none';
  });
}

/* ══════════════════════════════════════════════
   MONITORING
══════════════════════════════════════════════ */
function updateMonitoring() {
  apiFetch('/api/supervision')
    .then(function(data) {
      var s   = data.systeme || {};
      var set = function(id,v) { var e=document.getElementById(id); if(e) e.textContent=v; };
      var bar = function(id,pct,col) {
        var e=document.getElementById(id); if(!e) return;
        pct = pct||0;
        e.style.width = Math.min(100,pct)+'%';
        e.style.background = pct>85?'#ef4444':pct>65?'#f59e0b':col;
      };
      set('cpu-val',   (s.cpu||0)+'%');       bar('cpu-bar',  s.cpu||0, '#3b82f6');
      set('ram-val',   (s.ram_pct||0)+'%');   bar('ram-bar',  s.ram_pct||0, '#8b5cf6');
      set('ram-detail',(s.ram_used||0)+' MB / '+(s.ram_total||0)+' MB');
      set('disk-val',  (s.disk_pct||0)+'%');  bar('disk-bar', s.disk_pct||0, '#f59e0b');
      set('disk-detail',(s.disk_used||0)+' GB / '+(s.disk_total||0)+' GB');
      set('net-up',   '↑ '+(s.bytes_sent||0)+' KB');
      set('net-down', '↓ '+(s.bytes_recv||0)+' KB');
      var st = document.getElementById('sys-statut');
      if (st) {
        st.textContent = data.statut||'NORMAL';
        st.className = 'badge '+(data.statut==='NORMAL'?'badge-safe':
                                  data.statut==='WARNING'?'badge-high':'badge-critical');
      }
    })
    .catch(function() {});
}

/* ══════════════════════════════════════════════
   NETWORK TOPOLOGY
══════════════════════════════════════════════ */
function initTopology() {
  var svg = document.getElementById('topology-svg');
  if (!svg) return;
  var nodes = [
    {id:'fw', x:300,y:140,color:'#ef4444',label:'Firewall'},
    {id:'r1', x:150,y:80, color:'#f59e0b',label:'Router'},
    {id:'sw1',x:150,y:200,color:'#3b82f6',label:'Switch'},
    {id:'s1', x:50, y:60, color:'#10b981',label:'SRV-01'},
    {id:'s2', x:50, y:140,color:'#10b981',label:'SRV-02'},
    {id:'s3', x:50, y:220,color:'#8b5cf6',label:'DB-01'},
    {id:'ext',x:450,y:140,color:'#6b7280',label:'Internet'},
    {id:'att',x:520,y:80, color:'#ef4444',label:'Attaque'},
  ];
  var links = [
    {from:'fw',to:'r1',threat:false},{from:'fw',to:'sw1',threat:false},
    {from:'r1',to:'s1',threat:false},{from:'sw1',to:'s2',threat:false},
    {from:'sw1',to:'s3',threat:false},{from:'fw',to:'ext',threat:false},
    {from:'ext',to:'att',threat:true},
  ];
  var map = {};
  nodes.forEach(function(n){map[n.id]=n;});
  var html = '';
  links.forEach(function(l) {
    var a=map[l.from],b=map[l.to];
    if(!a||!b) return;
    html += '<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+
      '" class="topo-link'+(l.threat?' threat':' active')+'"/>';
  });
  nodes.forEach(function(n) {
    html += '<g class="topo-node" style="cursor:pointer" onclick="Toast.show(\''+n.label+'\',\'info\',1500)">' +
      '<circle cx="'+n.x+'" cy="'+n.y+'" r="22" fill="'+n.color+'18" stroke="'+n.color+'" stroke-width="1.5"/>' +
      '<text x="'+n.x+'" y="'+(n.y+5)+'" text-anchor="middle" style="fill:'+n.color+
      ';font-size:9px;font-weight:600;font-family:monospace">'+n.label.slice(0,4)+'</text>' +
      '<text x="'+n.x+'" y="'+(n.y+36)+'" text-anchor="middle" style="font-size:8px;fill:var(--muted)">'+n.label+'</text></g>';
  });
  svg.innerHTML = html;
}

/* ══════════════════════════════════════════════
   SOC TERMINAL
══════════════════════════════════════════════ */
var Terminal = {
  logs: [
    {t:'info',   msg:'[INIT] Smart NetSec SOC Platform v3.0'},
    {t:'success',msg:'[OK] nftables actif — netsec_filter'},
    {t:'info',   msg:'[IDS] Snort 3 en surveillance — eth0'},
    {t:'info',   msg:'[NET] Interface eth0 — 192.168.216.0/24'},
    {t:'warn',   msg:'[WARN] Port 445 (SMB) détecté'},
    {t:'error',  msg:'[ALERT] Scan Nmap depuis 192.168.216.50'},
    {t:'info',   msg:'[IDS] Règle ET SCAN déclenchée — SID:9000001'},
    {t:'warn',   msg:'[FW] Tentative SSH non autorisée'},
    {t:'success',msg:'[FW] AUTO-BLOCK: 192.168.216.50 bloquée'},
    {t:'info',   msg:'[CORR] Corrélation Scan+BruteForce'},
    {t:'error',  msg:'[CRITICAL] EternalBlue pattern — SID:9000003'},
    {t:'success',msg:'[BLOCK] nftables: drop ip saddr 192.168.216.50'},
    {t:'info',   msg:'[SCORE] Score recalculé — 78/100'},
  ],
  idx: 0,
  iv: null,
  start: function() {
    var body = document.getElementById('term-body');
    if (!body || this.iv) return;
    var self = this;
    this.iv = setInterval(function() {
      var log  = self.logs[self.idx++ % self.logs.length];
      var time = new Date().toLocaleTimeString('fr-FR');
      var line = document.createElement('div');
      line.className = 'term-line ' + log.t;
      line.innerHTML = '<span style="color:var(--muted)">' + time + '</span> ' + log.msg;
      body.appendChild(line);
      if (body.children.length > 60) body.removeChild(body.firstChild);
      body.scrollTop = body.scrollHeight;
    }, 2200);
  },
  stop: function() { if (this.iv) { clearInterval(this.iv); this.iv=null; } }
};

/* ══════════════════════════════════════════════
   STATIC DATA (Incidents, ThreatIntel, Assets, MITRE)
══════════════════════════════════════════════ */
var _Incidents = [
  {id:'INC-001',title:'Scan réseau massif détecté',severity:'critical',status:'investigating',analyst:'Admin',time:'14:02',ip:'192.168.216.50'},
  {id:'INC-002',title:'Brute force SSH',severity:'high',status:'mitigated',analyst:'Admin',time:'13:45',ip:'192.168.216.1'},
  {id:'INC-003',title:'Port SMB exposé',severity:'high',status:'open',analyst:'—',time:'12:30',ip:'192.168.216.1'},
  {id:'INC-004',title:'Trafic DNS suspect',severity:'medium',status:'resolved',analyst:'Admin',time:'11:15',ip:'192.168.216.2'},
];

function loadIncidents() {
  var el = document.getElementById('incidents-list');
  if (!el) return;
  var sc = {critical:'var(--red)',high:'var(--orange)',medium:'#ca8a04',low:'var(--blue)'};
  var sb = {investigating:'badge-high',mitigated:'badge-info',resolved:'badge-safe',open:'badge-critical'};
  el.innerHTML = _Incidents.map(function(inc) {
    return '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.65rem 0.85rem;' +
      'border-radius:var(--radius-sm);margin-bottom:0.35rem;background:var(--card2);' +
      'border:1px solid var(--border);border-left:2px solid '+sc[inc.severity]+'">' +
      '<div style="width:32px;height:32px;border-radius:var(--radius-sm);background:' +
      sc[inc.severity]+'14;color:'+sc[inc.severity]+';display:flex;align-items:center;' +
      'justify-content:center;font-size:0.9rem;flex-shrink:0">' +
      '<i class="fas fa-'+(inc.severity==='critical'?'skull':'exclamation-triangle')+'"></i></div>' +
      '<div style="flex:1;min-width:0">' +
      '<div style="font-size:0.78rem;font-weight:600;margin-bottom:0.12rem">'+inc.title+'</div>' +
      '<div style="font-size:0.65rem;color:var(--muted)">' +
      '<span style="color:'+sc[inc.severity]+';font-weight:700">'+inc.severity.toUpperCase()+'</span>' +
      ' · '+inc.ip+' · '+inc.time+' · '+inc.analyst+'</div></div>' +
      '<span class="badge '+(sb[inc.status]||'badge-info')+'">'+inc.status+'</span></div>';
  }).join('');
}

var _ThreatData = [
  {ip:'185.220.101.45',flag:'🇷🇺',type:'Tor Exit Node',score:95,level:'critical'},
  {ip:'45.142.212.18', flag:'🇳🇱',type:'Port Scanner', score:82,level:'high'},
  {ip:'89.248.167.131',flag:'🇳🇱',type:'Botnet C2',    score:91,level:'critical'},
  {ip:'103.35.74.55',  flag:'🇨🇳',type:'Brute Force',  score:78,level:'high'},
  {ip:'192.168.216.50',flag:'🔴', type:'Scan interne',  score:65,level:'medium'},
];

function loadThreatIntel() {
  var el = document.getElementById('threat-intel-list');
  if (!el) return;
  var col = {critical:'#ef4444',high:'#f59e0b',medium:'#ca8a04',low:'#3b82f6'};
  el.innerHTML = _ThreatData.map(function(t) {
    return '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border)">' +
      '<span>'+t.flag+'</span>' +
      '<code style="color:var(--red);min-width:130px;font-size:0.75rem">'+t.ip+'</code>' +
      '<div style="flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden">' +
      '<div style="height:100%;width:'+t.score+'%;background:'+col[t.level]+'"></div></div>' +
      '<span style="font-size:0.7rem;font-weight:700;color:'+col[t.level]+'">'+t.score+'</span>' +
      '<span style="font-size:0.65rem;color:var(--muted);min-width:80px">'+t.type+'</span>' +
      '<span class="badge badge-'+t.level+'">'+t.level.toUpperCase()+'</span>' +
      '<button class="action-btn red" onclick="Actions.bloquer(\''+t.ip+'\')" title="Bloquer">' +
      '<i class="fas fa-ban"></i></button></div>';
  }).join('');
}

var _Assets = [
  {name:'FW-MAIN', type:'Firewall',      ip:'192.168.216.1',   status:'online', icon:'fa-fire-alt',      col:'#ef4444'},
  {name:'SW-CORE', type:'Switch',         ip:'192.168.216.2',   status:'online', icon:'fa-network-wired', col:'#f59e0b'},
  {name:'SRV-WEB', type:'Serveur Web',    ip:'192.168.216.10',  status:'online', icon:'fa-server',        col:'#10b981'},
  {name:'SRV-DB',  type:'Base données',   ip:'192.168.216.11',  status:'warning',icon:'fa-database',      col:'#8b5cf6'},
  {name:'KALI-01', type:'Endpoint',       ip:'192.168.216.143', status:'online', icon:'fa-laptop',        col:'#3b82f6'},
  {name:'VM-WIN',  type:'Windows VM',     ip:'192.168.216.50',  status:'offline',icon:'fa-desktop',       col:'#6b7280'},
];

function loadAssets() {
  var el = document.getElementById('assets-list');
  if (!el) return;
  var sc = {online:'#10b981',warning:'#f59e0b',offline:'#ef4444'};
  var sb = {online:'badge-safe',warning:'badge-high',offline:'badge-critical'};
  el.innerHTML = _Assets.map(function(a) {
    return '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.65rem 0.85rem;border-bottom:1px solid var(--border)">' +
      '<div style="width:36px;height:36px;border-radius:var(--radius-sm);background:'+a.col+'14;' +
      'color:'+a.col+';display:flex;align-items:center;justify-content:center;font-size:0.95rem;flex-shrink:0">' +
      '<i class="fas '+a.icon+'"></i></div>' +
      '<div style="flex:1;min-width:0">' +
      '<div style="font-size:0.8rem;font-weight:600">'+a.name+'</div>' +
      '<div style="font-size:0.65rem;color:var(--muted)">'+a.type+' — <code>'+a.ip+'</code></div></div>' +
      '<span class="badge '+sb[a.status]+'">'+a.status.toUpperCase()+'</span></div>';
  }).join('');
}

var _Mitre = [
  {phase:'Reconnaissance',color:'#6b7280',techs:['T1595 Scan','T1590 Gather']},
  {phase:'Initial Access', color:'#ef4444',techs:['T1190 Exploit','T1078 Accounts']},
  {phase:'Execution',      color:'#f59e0b',techs:['T1059 CLI','T1053 Scheduler']},
  {phase:'Persistence',    color:'#f59e0b',techs:['T1547 Boot','T1136 Account']},
  {phase:'Privilege Esc',  color:'#ec4899',techs:['T1068 Exploit','T1055 Inject']},
  {phase:'Defense Eva',    color:'#06b6d4',techs:['T1027 Obfusc','T1070 Remove']},
  {phase:'Lateral Move',   color:'#3b82f6',techs:['T1021 Remote','T1210 Exploit']},
  {phase:'Exfiltration',   color:'#10b981',techs:['T1041 C2','T1048 Alt Proto']},
];
var _activePhases = ['Initial Access','Execution','Defense Eva'];

function loadMitre() {
  var el = document.getElementById('mitre-container');
  if (!el) return;
  el.innerHTML = _Mitre.map(function(p) {
    var active = _activePhases.indexOf(p.phase) >= 0;
    return '<div class="mitre-phase" style="'+(active?'border-color:'+p.color+';box-shadow:0 0 12px '+p.color+'30':'')+'">' +
      '<div class="mitre-phase-name" style="'+(active?'color:'+p.color:'')+'">' +p.phase+'</div>' +
      p.techs.map(function(t) {
        return '<div class="mitre-technique '+(active?'active':'')+'" style="' +
          (active?'border-color:'+p.color+';color:'+p.color:'')+'">' +t+'</div>';
      }).join('') + '</div>';
  }).join('');
}

/* ══════════════════════════════════════════════
   DEVICES — Filtrage + Tri + Ports
══════════════════════════════════════════════ */
var _devSortCol = 'ip';
var _devSortAsc = true;

var PORT_SVC = {
  '21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','53':'DNS','80':'HTTP',
  '110':'POP3','135':'MSRPC','139':'NetBIOS','143':'IMAP','443':'HTTPS',
  '445':'SMB','993':'IMAPS','1433':'MSSQL','3306':'MySQL','3389':'RDP',
  '4444':'MSF','5432':'PgSQL','5900':'VNC','8080':'HTTP-alt','5000':'Flask',
};

function filterDevices() {
  var q    = (document.getElementById('dev-search')   ?.value||'').toLowerCase();
  var niv  = (document.getElementById('dev-filter-niveau')?.value||'');
  var typ  = (document.getElementById('dev-filter-type')  ?.value||'');
  var vis  = 0;
  document.querySelectorAll('.device-row').forEach(function(row) {
    var txt = row.textContent.toLowerCase();
    var ok  = (!q   || txt.indexOf(q)>=0)
           && (!niv  || row.dataset.niveau===niv)
           && (!typ  || row.dataset.type.indexOf(typ)>=0);
    row.style.display = ok?'':'none';
    if (ok) vis++;
  });
  var cnt = document.getElementById('dev-count');
  if (cnt) cnt.textContent = vis + ' appareil(s)';
}

function sortDevices(col) {
  if (_devSortCol===col) _devSortAsc=!_devSortAsc;
  else { _devSortCol=col; _devSortAsc=true; }
  var tbody = document.getElementById('devices-tbody');
  if (!tbody) return;
  var rows = Array.from(tbody.querySelectorAll('.device-row'));
  rows.sort(function(a,b) {
    var va=a.dataset[col]||'', vb=b.dataset[col]||'';
    if (col==='score'){va=parseInt(va)||0; vb=parseInt(vb)||0;}
    return _devSortAsc ? (va<vb?-1:va>vb?1:0) : (va<vb?1:va>vb?-1:0);
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}

function renderPorts() {
  document.querySelectorAll('.port-render').forEach(function(el) {
    var raw = el.dataset.ports||'[]';
    var parent = el.parentElement;
    el.style.display='none';
    var ports=[];
    try {
      var parsed=JSON.parse(raw.replace(/'/g,'"'));
      if (Array.isArray(parsed)) {
        ports=parsed.map(function(p){
          if(typeof p==='object'){
            var num=String(p.PORT||p.port||p.p||'');
            return {num:num,svc:p.SERVICE||p.service||PORT_SVC[num]||''};
          }
          return {num:String(p),svc:PORT_SVC[String(p)]||''};
        }).filter(function(p){return p.num&&p.num!=='undefined';});
      }
    } catch(e) {
      var nums=(raw.match(/\d{2,5}/g)||[]);
      ports=[...new Set(nums)].slice(0,8).map(function(n){return {num:n,svc:PORT_SVC[n]||''};});
    }
    if (!ports.length){
      parent.innerHTML='<span style="color:var(--muted);font-size:0.72rem">—</span>';
      return;
    }
    var danger=['22','23','21','445','3389','4444','1433','3306'];
    parent.innerHTML=ports.slice(0,6).map(function(p){
      var d=danger.indexOf(p.num)>=0;
      var col=d?'var(--red)':'var(--blue)';
      var bg =d?'rgba(239,68,68,0.08)':'rgba(59,130,246,0.08)';
      return '<span title="Port '+p.num+(p.svc?' ('+p.svc+')':'')+'" style="font-size:0.62rem;' +
        'padding:0.1rem 0.35rem;background:'+bg+';border:1px solid '+col+'40;' +
        'border-radius:3px;white-space:nowrap;color:'+col+';font-weight:600">' +
        (p.svc?p.num+'/'+p.svc:p.num)+'</span>';
    }).join('')+(ports.length>6?'<span style="font-size:0.6rem;color:var(--muted)">+'+(ports.length-6)+'</span>':'');
  });
}

/* ══════════════════════════════════════════════
   ACTIONS GLOBALES
══════════════════════════════════════════════ */
var Actions = {
  bloquer: function(ip) {
    if (!confirm('Bloquer '+ip+' ?')) return;
    apiFetch('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison='+encodeURIComponent('Blocage dashboard'))
      .then(function(d) {
        Toast.show(d.msg||d.message||'✅ IP bloquée','success');
        updateFirewallStats();
        if (window.FW) FW.loadBlocked();
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  },
  debloquer: function(ip) {
    if (!confirm('Débloquer '+ip+' ?')) return;
    apiFetch('/api/firewall/debloquer/'+encodeURIComponent(ip))
      .then(function(d) {
        Toast.show(d.msg||d.message||'✅ IP débloquée','success');
        updateFirewallStats();
        if (window.FW) FW.loadBlocked();
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  },
  whitelist: function(ip) {
    if (!confirm('Whitelister '+ip+' ?')) return;
    apiPost('/api/firewall/whitelist/add',{ip:ip,raison:'Whitelist dashboard'})
      .then(function(d){Toast.show(d.message||'✅ Whitelistée','success');})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  },
  scan: function() {
    var btn=document.getElementById('btn-scan');
    if(btn){btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Scan...';}
    apiFetch('/lancer-scan')
      .then(function(){
        Toast.show('Scan lancé...','info');
        var iv=setInterval(function(){
          apiFetch('/api/scan-status').then(function(s){
            if(!s.actif){
              clearInterval(iv);
              if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-search"></i> Scanner';}
              Toast.show('Scan terminé !','success');
              setTimeout(function(){location.reload();},1200);
            }
          }).catch(function(){clearInterval(iv);});
        },5000);
      })
      .catch(function(e){
        if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-search"></i> Scanner';}
        Toast.show('Erreur scan: '+e.message,'error');
      });
  },
  traiterSuricata: function() {
    apiPost('/api/firewall/auto-response',{})
      .then(function(d){
        Toast.show((d.total||0)+' actions effectuées','success');
        updateFirewallStats();
        if(window.FW) FW.loadBlocked();
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  },
  importerSuricata: function() {
    apiFetch('/suricata/importer')
      .then(function(d){
        Toast.show((d.imported||0)+' alertes importées','success');
        if(window.IDS) IDS.refresh();
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  },
};

/* ══════════════════════════════════════════════
   MODULE FIREWALL
══════════════════════════════════════════════ */
var FW = (function() {

  function showTab(tab) {
    document.querySelectorAll('.fw-panel').forEach(function(p){p.style.display='none';});
    document.querySelectorAll('.fw-tab-btn').forEach(function(b){
      b.style.borderBottomColor='transparent'; b.style.color='var(--muted)';
    });
    var panel=document.getElementById('fw-panel-'+tab);
    var btn  =document.getElementById('fw-tab-'+tab);
    if(panel) panel.style.display='';
    if(btn)  {btn.style.borderBottomColor='var(--blue)'; btn.style.color='var(--blue)';}
    var loaders={blocked:loadBlocked,rules:loadRules,whitelist:loadWhitelist,
                 blacklist:loadBlacklist,connections:loadConnections,logs:loadLogs};
    if(loaders[tab]) loaders[tab]();
  }

  function loadBlocked() {
    apiFetch('/api/firewall/stats')
      .then(function(data) {
        var set=function(id,v){var e=document.getElementById(id);if(e) e.textContent=v;};
        set('fw-blocked',    data.nb_bloques  ||0);
        set('fw-wl',         data.nb_whitelist||0);
        set('fw-bl',         data.nb_blacklist||0);
        set('fw-rules-count',data.nb_rules    ||0);
        set('kpi-blocked',   data.nb_bloques  ||0);
        var tbody=document.getElementById('fw-blocked-tbody');
        if(!tbody) return;
        var bl=data.blocages||[];

        // Appliquer filtre de recherche
        var q=(document.getElementById('fw-search-blocked')?.value||'').toLowerCase();

        if(!bl.length){
          tbody.innerHTML='<tr><td colspan="6" class="no-data">'+
            '<i class="fas fa-check-circle" style="color:var(--green)"></i> Aucune IP bloquée</td></tr>';
          return;
        }
        var filtered=q?bl.filter(function(b){return (b.ip||'').indexOf(q)>=0||(b.raison||'').toLowerCase().indexOf(q)>=0;}):bl;
        if(!filtered.length){
          tbody.innerHTML='<tr><td colspan="6" class="no-data">Aucun résultat pour "'+q+'"</td></tr>';
          return;
        }
        tbody.innerHTML=filtered.map(function(b){
          var niv=b.niveau||'MANUAL';
          var bc=niv==='CRITICAL'?'critical':niv==='HIGH'?'high':'info';
          var ip=(b.ip||'').replace(/'/g,"\\'");
          return '<tr>'+
            '<td><code style="font-size:0.8rem">'+(b.ip||'—')+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted);max-width:220px;overflow:hidden;'+
            'text-overflow:ellipsis;white-space:nowrap" title="'+(b.raison||'')+'">'+(b.raison||'—')+'</td>'+
            '<td><span class="badge badge-'+bc+'">'+niv+'</span></td>'+
            '<td style="font-size:0.7rem;color:'+(b.auto_block?'var(--orange)':'var(--muted)')+';font-weight:600">'+
            (b.auto_block?'AUTO':'Manuel')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">'+
            (b.date_blocage||'').slice(0,16)+'</td>'+
            '<td>'+
            '<button class="action-btn green" title="Débloquer '+b.ip+'" onclick="FW.unblock(\''+ip+'\')">'+
            '<i class="fas fa-lock-open"></i></button>'+
            '</td></tr>';
        }).join('');
      })
      .catch(function(e){
        var tb=document.getElementById('fw-blocked-tbody');
        if(tb) tb.innerHTML='<tr><td colspan="6" class="no-data" style="color:var(--red)">Erreur: '+e.message+'</td></tr>';
      });
  }

  function loadRules() {
    apiFetch('/api/firewall/rules')
      .then(function(rules){
        var tbody=document.getElementById('fw-rules-tbody');
        if(!tbody) return;
        if(!rules.length){
          tbody.innerHTML='<tr><td colspan="10" class="no-data">Aucune règle — cliquez "Ajouter règle"</td></tr>';
          return;
        }
        tbody.innerHTML=rules.map(function(r){
          var rid=(r.rule_id||String(r.id)||'').replace(/'/g,"\\'");
          return '<tr>'+
            '<td style="font-size:0.62rem;color:var(--muted)">'+(r.rule_id||r.id||'—').toString().slice(0,8)+'</td>'+
            '<td><span class="badge badge-'+(r.type==='BLOCK'?'critical':r.type==='ALLOW'?'safe':'info')+'">'+(r.type||'—')+'</span></td>'+
            '<td><code>'+(r.ip||'*')+'</code></td>'+
            '<td>'+(r.port||'*')+'</td>'+
            '<td><span class="badge badge-info">'+(r.protocole||'all')+'</span></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(r.direction||'INPUT')+'</td>'+
            '<td>'+(r.priorite||100)+'</td>'+
            '<td><span class="badge '+(r.actif?'badge-safe':'badge-medium')+'">'+(r.actif?'Actif':'Inactif')+'</span></td>'+
            '<td style="font-size:0.62rem;color:var(--muted);white-space:nowrap">'+(r.date_create||'').slice(0,16)+'</td>'+
            '<td style="white-space:nowrap">'+
            '<button class="action-btn" onclick="FW.toggleRule(\''+rid+'\','+(r.actif?0:1)+')" title="'+(r.actif?'Désactiver':'Activer')+'">'+
            '<i class="fas fa-'+(r.actif?'pause':'play')+'"></i></button>'+
            '<button class="action-btn red" onclick="FW.deleteRule(\''+rid+'\')" title="Supprimer">'+
            '<i class="fas fa-trash"></i></button>'+
            '</td></tr>';
        }).join('');
      })
      .catch(function(e){console.error('loadRules:',e);});
  }

  function loadWhitelist() {
    apiFetch('/api/firewall/whitelist')
      .then(function(list){
        var tbody=document.getElementById('fw-wl-tbody');
        if(!tbody) return;
        var el=document.getElementById('fw-wl'); if(el) el.textContent=list.length;
        var q=(document.getElementById('wl-search')?.value||'').toLowerCase();
        var filtered=q?list.filter(function(w){return (w.ip||'').indexOf(q)>=0;}):list;
        if(!filtered.length){
          tbody.innerHTML='<tr><td colspan="4" class="no-data">'+(q?'Aucun résultat':'Whitelist vide')+'</td></tr>';
          return;
        }
        tbody.innerHTML=filtered.map(function(w){
          var ip=(w.ip||'').replace(/'/g,"\\'");
          return '<tr>'+
            '<td><code style="color:var(--green)">'+w.ip+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(w.raison||'—')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem">'+(w.date_ajout||'').slice(0,16)+'</td>'+
            '<td><button class="action-btn red" title="Retirer" onclick="FW.removeWhitelist(\''+ip+'\')">'+
            '<i class="fas fa-times"></i></button></td></tr>';
        }).join('');
      })
      .catch(function(e){console.error('loadWhitelist:',e);});
  }

  function loadBlacklist() {
    apiFetch('/api/firewall/blacklist')
      .then(function(list){
        var tbody=document.getElementById('fw-bl-tbody');
        if(!tbody) return;
        var el=document.getElementById('fw-bl'); if(el) el.textContent=list.length;
        var q=(document.getElementById('bl-search')?.value||'').toLowerCase();
        var filtered=q?list.filter(function(b){return (b.ip||'').indexOf(q)>=0;}):list;
        if(!filtered.length){
          tbody.innerHTML='<tr><td colspan="5" class="no-data">'+(q?'Aucun résultat':'Blacklist vide')+'</td></tr>';
          return;
        }
        tbody.innerHTML=filtered.map(function(b){
          var ip=(b.ip||'').replace(/'/g,"\\'");
          return '<tr>'+
            '<td><code style="color:var(--red)">'+b.ip+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(b.raison||'—')+'</td>'+
            '<td style="font-size:0.7rem;color:var(--muted)">'+(b.source||'manual')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem">'+(b.date_ajout||'').slice(0,16)+'</td>'+
            '<td style="white-space:nowrap">'+
            '<button class="action-btn red" title="Bloquer maintenant" onclick="FW.block(\''+ip+'\',\'Depuis blacklist\')">'+
            '<i class="fas fa-ban"></i></button>'+
            '<button class="action-btn" title="Retirer" onclick="FW.removeBlacklist(\''+ip+'\')">'+
            '<i class="fas fa-times"></i></button></td></tr>';
        }).join('');
      })
      .catch(function(e){console.error('loadBlacklist:',e);});
  }

  function loadConnections() {
    var tbody=document.getElementById('fw-conn-tbody');
    if(!tbody) return;
    tbody.innerHTML='<tr><td colspan="8" class="no-data"><i class="fas fa-spinner fa-spin"></i></td></tr>';
    apiFetch('/api/firewall/connections')
      .then(function(conns){
        if(!conns.length){tbody.innerHTML='<tr><td colspan="8" class="no-data">Aucune connexion</td></tr>';return;}
        tbody.innerHTML=conns.map(function(c){
          return '<tr style="'+(c.suspicious?'background:rgba(239,68,68,0.06)':'')+'">' +
            '<td><span class="badge badge-info">'+(c.proto||'—')+'</span></td>' +
            '<td style="font-size:0.7rem;color:var(--muted)">'+(c.state||'—')+'</td>' +
            '<td><code>'+(c.local_ip||'—')+'</code></td>' +
            '<td style="font-size:0.72rem">'+(c.local_port||'—')+'</td>' +
            '<td><code style="color:'+(c.suspicious?'var(--red)':'inherit')+'">'+(c.remote_ip||'—')+'</code></td>' +
            '<td style="font-size:0.72rem">'+(c.remote_port||'—')+'</td>' +
            '<td style="font-size:0.7rem;color:var(--muted)">'+(c.process||'—')+'</td>' +
            '<td>'+(c.suspicious?'<span class="badge badge-critical">SUSPECT</span>':'<span class="badge badge-safe">OK</span>')+'</td></tr>';
        }).join('');
      })
      .catch(function(){tbody.innerHTML='<tr><td colspan="8" class="no-data">Erreur chargement</td></tr>';});
  }

  function loadLogs() {
    apiFetch('/api/firewall/logs?limit=50')
      .then(function(logs){
        var tbody=document.getElementById('fw-logs-tbody');
        if(!tbody) return;
        if(!logs.length){tbody.innerHTML='<tr><td colspan="6" class="no-data">Aucun log</td></tr>';return;}
        tbody.innerHTML=logs.map(function(l){
          var bl=['BLOCK','BLOCKED'].indexOf(l.action)>=0;
          return '<tr>'+
            '<td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">'+(l.timestamp||'').slice(0,19)+'</td>'+
            '<td><span class="badge badge-'+(bl?'critical':l.action==='UNBLOCK'?'safe':'info')+'">'+(l.action||'—')+'</span></td>'+
            '<td><code style="color:'+(bl?'var(--red)':'inherit')+'">'+(l.ip_src||'—')+'</code></td>'+
            '<td><code>'+(l.ip_dst||'—')+'</code></td>'+
            '<td style="font-size:0.72rem">'+(l.port_dst||'—')+'</td>'+
            '<td><span class="badge badge-info">'+(l.protocole||'—')+'</span></td></tr>';
        }).join('');
      })
      .catch(function(e){console.error('loadLogs:',e);});
  }

  // Actions
  function block(ip, raison) {
    if(!ip||ip==='—'){Toast.show('IP invalide','error');return;}
    var r=raison||prompt('Raison :','Blocage manuel');
    if(r===null) return;
    apiFetch('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison='+encodeURIComponent(r))
      .then(function(d){Toast.show(d.message||d.msg||'✅ Bloquée',d.success===false?'error':'success');loadBlocked();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function unblock(ip) {
    if(!ip||ip==='—'){Toast.show('IP invalide','error');return;}
    if(!confirm('Débloquer '+ip+' ?')) return;
    apiFetch('/api/firewall/debloquer/'+encodeURIComponent(ip))
      .then(function(d){Toast.show(d.message||d.msg||'✅ Débloquée',d.success===false?'error':'success');loadBlocked();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function addWhitelist() {
    var inp=document.getElementById('wl-ip-input');
    var ip=(inp?.value||'').trim();
    if(!ip){Toast.show('Entrez une IP','error');if(inp)inp.focus();return;}
    var raison=(document.getElementById('wl-raison-input')?.value||'').trim()||'Whitelist manuelle';
    apiPost('/api/firewall/whitelist/add',{ip:ip,raison:raison})
      .then(function(d){
        Toast.show(d.message||'✅ Whitelistée',d.success===false?'error':'success');
        if(d.success!==false){if(inp)inp.value='';loadWhitelist();updateFirewallStats();}
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function removeWhitelist(ip) {
    if(!confirm('Retirer '+ip+' de la whitelist ?')) return;
    apiPost('/api/firewall/whitelist/'+encodeURIComponent(ip)+'/remove',{})
      .then(function(d){Toast.show(d.message||'✅ Retiré','success');loadWhitelist();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function addBlacklist() {
    var inp=document.getElementById('bl-ip-input');
    var ip=(inp?.value||'').trim();
    if(!ip){Toast.show('Entrez une IP','error');if(inp)inp.focus();return;}
    var raison=(document.getElementById('bl-raison-input')?.value||'').trim()||'Blacklist manuelle';
    apiPost('/api/firewall/blacklist/add',{ip:ip,raison:raison,source:'manual'})
      .then(function(d){
        Toast.show(d.message||'✅ Blacklistée',d.success===false?'error':'success');
        if(d.success!==false){if(inp)inp.value='';loadBlacklist();updateFirewallStats();}
      })
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function removeBlacklist(ip) {
    if(!confirm('Retirer '+ip+' de la blacklist ?')) return;
    apiPost('/api/firewall/blacklist/'+encodeURIComponent(ip)+'/remove',{})
      .then(function(d){Toast.show(d.message||'✅ Retiré','success');loadBlacklist();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function toggleRule(rid,actif) {
    apiPost('/api/firewall/rules/'+rid+'/toggle',{actif:actif})
      .then(function(d){Toast.show(d.message||'Règle MAJ','success');loadRules();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function deleteRule(rid) {
    if(!confirm('Supprimer cette règle ?')) return;
    apiPost('/api/firewall/rules/'+rid+'/delete',{})
      .then(function(d){Toast.show(d.message||'✅ Supprimée','success');loadRules();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function openBlockModal() {
    var ip=prompt('IP à bloquer :',''); if(!ip?.trim()) return;
    var r=prompt('Raison :','Blocage manuel')||'Blocage manuel';
    block(ip.trim(),r);
  }

  function openRuleModal() {
    var ip=prompt('IP source (* = tout) :','*'); if(ip===null) return;
    var port=prompt('Port (vide = tout) :','')||null;
    var proto=prompt('Protocole (tcp/udp/all) :','tcp')||'tcp';
    var type_=prompt('Action (BLOCK/ALLOW) :','BLOCK')||'BLOCK';
    var raison=prompt('Commentaire :','Règle manuelle')||'Règle manuelle';
    apiPost('/api/firewall/rules/add',{ip:ip||'*',port:port,proto:proto,type:type_,raison:raison})
      .then(function(d){Toast.show(d.message||'✅ Règle ajoutée','success');loadRules();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function autoResponse() {
    apiPost('/api/firewall/auto-response',{})
      .then(function(d){Toast.show(d.message||(d.total||0)+' actions','success');loadBlocked();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function searchBlocked() {
    loadBlocked(); // loadBlocked lit déjà fw-search-blocked
  }

  function searchWhitelist() { loadWhitelist(); }
  function searchBlacklist() { loadBlacklist(); }

  function init() { showTab('blocked'); updateFirewallStats(); }


  // Filtre générique sur un tbody par texte
  function filterTable(tbodyId, q) {
    q = (q||'').toLowerCase().trim();
    var tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    var count = 0;
    tbody.querySelectorAll('tr').forEach(function(row) {
      var match = !q || row.textContent.toLowerCase().indexOf(q) >= 0;
      row.style.display = match ? '' : 'none';
      if (match) count++;
    });
  }

  // Recherche dans IPs Bloquées (recharge depuis API)
  function searchBlocked() {
    var q = (document.getElementById('fw-blocked-search')?.value ||
             document.getElementById('fw-search-blocked')?.value || '').toLowerCase().trim();
    if (!q) { loadBlocked(); return; }
    // Filtrer les lignes visibles
    filterTable('fw-blocked-tbody', q);
  }

  return {
    showTab:showTab, loadBlocked:loadBlocked, loadRules:loadRules,
    loadWhitelist:loadWhitelist, loadBlacklist:loadBlacklist,
    loadConnections:loadConnections, loadLogs:loadLogs,
    block:block, unblock:unblock,
    addWhitelist:addWhitelist, removeWhitelist:removeWhitelist,
    addBlacklist:addBlacklist, removeBlacklist:removeBlacklist,
    toggleRule:toggleRule, deleteRule:deleteRule,
    openBlockModal:openBlockModal, openRuleModal:openRuleModal,
    autoResponse:autoResponse,
    filterTable:filterTable, searchBlocked:searchBlocked, searchWhitelist:searchWhitelist,
    searchBlacklist:searchBlacklist, init:init,
  };
})();

/* ══════════════════════════════════════════════
   MODULE IDS
══════════════════════════════════════════════ */
var IDS = (function() {
  var allAlerts=[];

  function refresh() {
    apiFetch('/api/ids/alerts?limit=100')
      .then(function(alerts){allAlerts=alerts;renderAlerts(alerts);updateStats();loadTopIPs();})
      .catch(function(e){console.error('IDS refresh:',e);});
  }

  function renderAlerts(alerts) {
    var tbody=document.getElementById('ids-alerts-tbody');
    if(!tbody) return;
    var cnt=document.getElementById('ids-count-display');
    if(cnt) cnt.textContent=alerts.length+' alerte(s)';
    if(!alerts.length){
      tbody.innerHTML='<tr><td colspan="11" class="no-data">Aucune alerte — '+
        '<button onclick="IDS.importDemo()" class="card-action" style="margin-left:0.5rem">Charger démo</button></td></tr>';
      return;
    }
    tbody.innerHTML=alerts.map(function(a,idx){
      var ip=(a.src_ip||'').replace(/'/g,"\\'");
      return '<tr onclick="IDS.showDetail('+idx+')" style="cursor:pointer" '+
        'onmouseover="this.style.background=\'rgba(59,130,246,0.06)\'" '+
        'onmouseout="this.style.background=\'\'">' +
        '<td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">'+(a.timestamp||'').slice(0,19)+'</td>' +
        '<td><code style="color:var(--red)">'+(a.src_ip||'—')+'</code></td>' +
        '<td style="font-size:0.72rem;color:var(--muted)">'+(a.src_port||'—')+'</td>' +
        '<td><code>'+(a.dst_ip||a.dest_ip||'—')+'</code></td>' +
        '<td style="font-size:0.72rem;color:var(--muted)">'+(a.dst_port||'—')+'</td>' +
        '<td><span class="badge badge-info">'+(a.protocole||'—')+'</span></td>' +
        '<td style="font-size:0.75rem;font-weight:700;color:'+(a.priority===1?'#ef4444':a.priority===2?'#f59e0b':'var(--muted)')+'">P'+(a.priority||3)+'</td>' +
        '<td style="font-size:0.72rem;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+(a.message||'')+'">'+(a.message||'—')+'</td>' +
        '<td><span class="badge badge-'+(a.niveau==='CRITICAL'?'critical':a.niveau==='HIGH'?'high':a.niveau==='MEDIUM'?'medium':'low')+'">'+(a.niveau||'—')+'</span></td>' +
        '<td style="font-size:0.65rem;color:'+(a.action_prise==='BLOCKED'?'var(--red)':a.action_prise==='MONITOR'?'var(--orange)':'var(--green)')+'">'+(a.action_prise||'LOG')+'</td>' +
        '<td onclick="event.stopPropagation()">' +
        '<button class="action-btn red" onclick="IDS.blockIP(\''+ip+'\')" title="Bloquer">' +
        '<i class="fas fa-ban"></i></button></td></tr>';
    }).join('');
  }

  function updateStats() {
    apiFetch('/api/ids/stats').then(function(s){
      var set=function(id,v){var e=document.getElementById(id);if(e) e.textContent=v;};
      set('ids-stat-critical',s.critical||0); set('ids-stat-high',s.high||0);
      set('ids-stat-medium',s.medium||0);     set('ids-stat-low',s.low||0);
      set('ids-stat-total',s.total||0);
    }).catch(function(){});
  }

  function loadTopIPs() {
    apiFetch('/api/ids/stats').then(function(s){
      var el=document.getElementById('ids-top-ips'); if(!el) return;
      var ips=s.top_ips||[];
      if(!ips.length){el.innerHTML='<p class="no-data">Aucun attaquant</p>';return;}
      var max=ips[0]?.nb||1;
      el.innerHTML=ips.map(function(ip){
        return '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem;border-bottom:1px solid var(--border)">' +
          '<code style="color:var(--red);min-width:130px;font-size:0.75rem">'+ip.src_ip+'</code>' +
          '<div style="flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden">' +
          '<div style="height:100%;width:'+Math.round(ip.nb/max*100)+'%;background:linear-gradient(90deg,#dc2626,#ef4444)"></div></div>' +
          '<span style="font-size:0.75rem;font-weight:700;color:var(--red)">'+ip.nb+'</span>' +
          '<button class="action-btn red" onclick="IDS.blockIP(\''+ip.src_ip+'\')" title="Bloquer">' +
          '<i class="fas fa-ban"></i></button></div>';
      }).join('');
    }).catch(function(){});
  }

  function applyFilters() {
    var level=(document.getElementById('ids-filter-level')?.value||'');
    var proto=(document.getElementById('ids-filter-proto')?.value||'');
    var q=(document.getElementById('ids-search')?.value||'').toLowerCase();
    renderAlerts(allAlerts.filter(function(a){
      return (!level||a.niveau===level) && (!proto||a.protocole===proto) &&
             (!q||((a.message||'').toLowerCase().indexOf(q)>=0)||
              (a.src_ip||'').indexOf(q)>=0||(a.dst_ip||'').indexOf(q)>=0);
    }));
  }

  function clearFilters() {
    ['ids-filter-level','ids-filter-proto','ids-search'].forEach(function(id){
      var e=document.getElementById(id); if(e) e.value='';
    });
    renderAlerts(allAlerts);
  }

  function showDetail(idx) {
    var a=allAlerts[idx]; if(!a) return;
    alert('🛡️ Détail Alerte Snort\n\n'+
      'Signature : '+(a.message||'—')+'\n'+
      'SID       : '+(a.sid||'—')+' rev.'+(a.revision||'—')+'\n'+
      'Source    : '+(a.src_ip||'—')+':'+(a.src_port||'—')+'\n'+
      'Dest      : '+(a.dst_ip||'—')+':'+(a.dst_port||'—')+'\n'+
      'Protocole : '+(a.protocole||'—')+'\n'+
      'Priorité  : P'+(a.priority||'—')+' — '+(a.niveau||'—')+'\n'+
      'Action    : '+(a.action_prise||'—')+'\n'+
      'Timestamp : '+(a.timestamp||'—'));
  }

  function blockIP(ip) {
    if(!ip||ip==='—'){Toast.show('IP invalide','error');return;}
    if(!confirm('Bloquer '+ip+' ?')) return;
    apiFetch('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison='+encodeURIComponent('Blocage IDS Snort'))
      .then(function(d){Toast.show(d.message||d.msg||'✅ Bloquée','success');FW.loadBlocked();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function autoBlock() {
    apiPost('/api/firewall/auto-response',{})
      .then(function(d){Toast.show(d.message||(d.total||0)+' actions','success');refresh();FW.loadBlocked();updateFirewallStats();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function importDemo() {
    apiFetch('/api/ids/inject-demo')
      .then(function(d){Toast.show((d.injected||0)+' alertes démo chargées','success');setTimeout(refresh,600);})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function startSnort() {
    apiFetch('/api/ids/start')
      .then(function(d){Toast.show(d.message||'Snort démarré','success');checkSnortStatus();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function stopSnort() {
    if(!confirm('Arrêter Snort ?')) return;
    apiFetch('/api/ids/stop')
      .then(function(d){Toast.show(d.message||'Snort arrêté','info');checkSnortStatus();})
      .catch(function(e){Toast.show('Erreur: '+e.message,'error');});
  }

  function checkSnortStatus() {
    apiFetch('/api/ids/status').then(function(s){
      var dot=document.getElementById('snort-status-dot');
      var txt=document.getElementById('snort-status-text');
      if(dot)  dot.style.color=s.running?'var(--green)':'var(--muted)';
      if(txt)  txt.textContent=s.running?'✅ Actif — '+(s.version||'Snort 3'):'⚪ Inactif (mode démo)';
    }).catch(function(){});
  }

  function reloadRules() {
    var el=document.getElementById('ids-rules-list'); if(!el) return;
    el.innerHTML='<p style="color:var(--muted)">Chargement...</p>';
    apiFetch('/api/ids/rules').then(function(rules){
      if(!rules.length){el.innerHTML='<p style="color:var(--muted)">Aucune règle</p>';return;}
      el.innerHTML=rules.map(function(r){
        var line=r.rule||'';
        return '<div style="padding:0.2rem 0;border-bottom:1px solid #1a2a3a;font-size:0.68rem">'+
          line.replace(/^(alert|drop)/,'<span style="color:#f59e0b">$1</span>')
              .replace(/(msg:"[^"]*")/g,'<span style="color:#10b981">$1</span>')
              .replace(/(sid:\d+)/g,'<span style="color:#3b82f6">$1</span>')+'</div>';
      }).join('');
      Toast.show('Règles rechargées','success');
    }).catch(function(e){el.innerHTML='<p style="color:var(--red)">Erreur: '+e.message+'</p>';});
  }

  function init() {
    checkSnortStatus();
    refresh();
    setInterval(refresh,30000);
    setInterval(checkSnortStatus,15000);
  }

  return {
    refresh:refresh, renderAlerts:renderAlerts, applyFilters:applyFilters,
    clearFilters:clearFilters, showDetail:showDetail, blockIP:blockIP,
    autoBlock:autoBlock, importDemo:importDemo, startSnort:startSnort,
    stopSnort:stopSnort, checkSnortStatus:checkSnortStatus,
    reloadRules:reloadRules, loadTopIPs:loadTopIPs, updateStats:updateStats, init:init,
  };
})();

/* ══════════════════════════════════════════════
   INIT GLOBAL
══════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function() {
  Theme.init();
  initTopbarDate();
  loadInsights();
  updateFirewallStats();
  loadIncidents();
  loadThreatIntel();
  loadAssets();
  loadMitre();

  Nav.register('firewall',           function(){FW.init();});
  Nav.register('alerts',             function(){IDS.init();});
  Nav.register('timeline',           loadTimeline);
  Nav.register('ai-page',            loadAISysResume);
  Nav.register('monitoring',         updateMonitoring);
  Nav.register('smart-correlations', loadCorrelations);
  Nav.register('network-topology',   initTopology);
  Nav.register('soc-terminal',       function(){Terminal.start();});
  Nav.register('reports',            loadReports);
  Nav.register('incidents',          loadIncidents);
  Nav.register('threat-intel',       loadThreatIntel);
  Nav.register('assets',             loadAssets);
  Nav.register('mitre',              loadMitre);


  // Devices — connecter Enter sur la barre de recherche
  var devSearch = document.getElementById('dev-search');
  if (devSearch) {
    devSearch.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') filterDevices();
    });
  }

  // Firewall — Enter sur champs de recherche
  ['fw-blocked-search','wl-search','bl-search'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        if (id === 'fw-blocked-search') FW.filterTable('fw-blocked-tbody', e.target.value);
        else if (id === 'wl-search') FW.loadWhitelist();
        else if (id === 'bl-search') FW.loadBlacklist();
      }
    });
  });
  setInterval(updateFirewallStats, 20000);
  setInterval(updateMonitoring,    12000);
  setInterval(loadInsights,        60000);
  Terminal.start();
  updateMonitoring();
  setTimeout(renderPorts, 200);

  document.getElementById('help-modal')?.addEventListener('click', function(e){
    if(e.target===this) Help.close();
  });

  document.addEventListener('keydown', function(e){
    if(e.ctrlKey && e.key==='k'){e.preventDefault();document.getElementById('search-input')?.focus();}
    if(e.key==='Escape') Help.close();
  });
});

/* ══════════════════════════════════════════════
   EXPOSITION WINDOW — TOUS LES GLOBALS
══════════════════════════════════════════════ */
window.Theme    = Theme;
window.Nav      = Nav;
window.Toast    = Toast;
window.FW       = FW;
window.IDS      = IDS;
window.Terminal = Terminal;
window.Actions  = Actions;
window.Search   = Search;
window.Help     = Help;

// Fonctions globales appelées par onclick dans HTML
window.showPage         = function(name, el) { Nav.show(name, el); };
window.toggleTheme      = function()         { Theme.toggle(); };
window.handleSearch     = function(v)        { Search.handle(v); };
window.toggleHelp       = function()         { Help.toggle(); };
window.helpSearch       = helpSearch;
window.helpGoTo         = helpGoTo;
window.toggleAI         = function()         { if(window.AI) AI.toggle(); };
window.bloquerIP        = function(ip)       { Actions.bloquer(ip); };
window.debloquerIP      = function(ip)       { Actions.debloquer(ip); };
window.whitelistIP      = function(ip)       { Actions.whitelist(ip); };
window.lancerScan       = function()         { Actions.scan(); };
window.traiterSuricata  = function()         { Actions.traiterSuricata(); };
window.importerSuricata = function()         { Actions.importerSuricata(); };
window.generateReport   = generateReport;
window.filterReports    = filterReports;
window.loadReports      = loadReports;
window.filterDevices    = filterDevices;
window.sortDevices      = sortDevices;
window.renderPorts      = renderPorts;
window.loadTimeline     = loadTimeline;
window.loadCorrelations = loadCorrelations;
window.updateMonitoring = updateMonitoring;
window.loadIncidents    = loadIncidents;
window.loadThreatIntel  = loadThreatIntel;
window.loadAssets       = loadAssets;
window.loadMitre        = loadMitre;
window.initTopology     = initTopology;
window.updateFirewallStats = updateFirewallStats;


var FW = (function() {
  'use strict';

  function _api(url, opts) {
    return fetch(url, Object.assign({credentials:'same-origin'}, opts||{}))
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP '+r.status+' '+url);
        return r.json();
      });
  }

  function _post(url, data) {
    return _api(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(data||{})
    });
  }

  /* ─── TABS ─────────────────────────────────── */
  function showTab(tab) {
    document.querySelectorAll('.fw-panel').forEach(function(p){p.style.display='none';});
    document.querySelectorAll('.fw-tab-btn').forEach(function(b){
      b.style.borderBottomColor='transparent';
      b.style.color='var(--muted)';
    });
    var panel = document.getElementById('fw-panel-'+tab);
    var btn   = document.getElementById('fw-tab-'+tab);
    if (panel) panel.style.display='';
    if (btn)   { btn.style.borderBottomColor='var(--blue)'; btn.style.color='var(--blue)'; }
    var map = {
      blocked:loadBlocked, rules:loadRules,
      whitelist:loadWhitelist, blacklist:loadBlacklist,
      connections:loadConnections, logs:loadLogs
    };
    if (map[tab]) map[tab]();
  }

  /* ─── IPS BLOQUÉES ──────────────────────────── */
  function loadBlocked() {
    _api('/api/firewall/stats')
      .then(function(d) {
        function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
        set('fw-blocked',     d.nb_bloques   ||0);
        set('fw-wl',          d.nb_whitelist ||0);
        set('fw-bl',          d.nb_blacklist ||0);
        set('fw-rules-count', d.nb_rules     ||0);
        set('kpi-blocked',    d.nb_bloques   ||0);

        var tbody = document.getElementById('fw-blocked-tbody');
        if (!tbody) return;
        var bl = d.blocages||[];

        // Filtre recherche
        var q = '';
        var si = document.getElementById('fw-blocked-search');
        if (si) q = (si.value||'').toLowerCase().trim();

        if (!bl.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-data">'+
            '<i class="fas fa-check-circle" style="color:var(--green)"></i> Aucune IP bloquée</td></tr>';
          return;
        }
        var list = q ? bl.filter(function(b){
          return (b.ip||'').indexOf(q)>=0 || (b.raison||'').toLowerCase().indexOf(q)>=0;
        }) : bl;

        if (!list.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-data">Aucun résultat pour "'+q+'"</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(function(b) {
          var ip  = (b.ip||'').replace(/'/g,"\'");
          var niv = b.niveau||'MANUAL';
          var bc  = niv==='CRITICAL'?'critical':niv==='HIGH'?'high':'info';
          return '<tr>'+
            '<td><code style="font-size:0.8rem">'+(b.ip||'—')+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+(b.raison||'')+'">'+(b.raison||'—')+'</td>'+
            '<td><span class="badge badge-'+bc+'">'+niv+'</span></td>'+
            '<td style="font-size:0.7rem;color:'+(b.auto_block?'var(--orange)':'var(--muted)')+'">'+
              (b.auto_block?'AUTO':'Manuel')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">'+(b.date_blocage||'').slice(0,16)+'</td>'+
            '<td>'+
              '<button class="action-btn green" onclick="FW.unblock('\''+ip+'\'')" title="Débloquer">'+
                '<i class="fas fa-lock-open"></i>'+
              '</button>'+
            '</td>'+
          '</tr>';
        }).join('');
      })
      .catch(function(e) {
        Toast.show('Erreur chargement blocages: '+e.message,'error');
      });
  }

  /* ─── RÈGLES ────────────────────────────────── */
  function loadRules() {
    _api('/api/firewall/rules')
      .then(function(rules) {
        var tbody = document.getElementById('fw-rules-tbody');
        if (!tbody) return;
        if (!rules.length) {
          tbody.innerHTML = '<tr><td colspan="9" class="no-data">Aucune règle — cliquez "Ajouter règle"</td></tr>';
          return;
        }
        tbody.innerHTML = rules.map(function(r) {
          var rid = (r.rule_id||String(r.id||'')).replace(/'/g,"\'");
          var actif = r.actif ? 1 : 0;
          return '<tr>'+
            '<td><code style="font-size:0.7rem;color:var(--muted)">'+(r.rule_id||r.id||'—').toString().slice(0,10)+'</code></td>'+
            '<td><span class="badge badge-'+(r.type==='BLOCK'?'critical':r.type==='ALLOW'?'safe':'info')+'">'+(r.type||'—')+'</span></td>'+
            '<td><code>'+(r.ip||'*')+'</code></td>'+
            '<td style="font-size:0.72rem">'+(r.port||'*')+'</td>'+
            '<td><span class="badge badge-info">'+(r.protocole||'all')+'</span></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(r.direction||'INPUT')+'</td>'+
            '<td><span class="badge '+(actif?'badge-safe':'badge-medium')+'">'+(actif?'Actif':'Inactif')+'</span></td>'+
            '<td style="color:var(--muted);font-size:0.62rem;white-space:nowrap">'+(r.date_create||'').slice(0,16)+'</td>'+
            '<td style="white-space:nowrap;display:flex;gap:2px">'+
              '<button class="action-btn" data-rid="'+rid+'" onclick="FW.toggleRule(this.dataset.rid,'+(actif?0:1)+')" '+
                'title="'+(actif?'Désactiver':'Activer')+'" style="font-size:0.7rem">'+
                '<i class="fas fa-'+(actif?'pause':'play')+'"></i>'+
              '</button>'+
              '<button class="action-btn red" data-rid="'+rid+'" onclick="FW.deleteRule(this.dataset.rid)" title="Supprimer" style="font-size:0.7rem">'+
                '<i class="fas fa-trash"></i>'+
              '</button>'+
            '</td>'+
          '</tr>';
        }).join('');
      })
      .catch(function(e){ Toast.show('Erreur règles: '+e.message,'error'); });
  }

  /* ─── WHITELIST ─────────────────────────────── */
  function loadWhitelist() {
    _api('/api/firewall/whitelist')
      .then(function(list) {
        var tbody = document.getElementById('fw-wl-tbody');
        if (!tbody) return;
        var el = document.getElementById('fw-wl');
        if (el) el.textContent = list.length;

        var q = (document.getElementById('wl-search')?.value||'').toLowerCase().trim();
        var filtered = q ? list.filter(function(w){return (w.ip||'').indexOf(q)>=0;}) : list;

        if (!filtered.length) {
          tbody.innerHTML = '<tr><td colspan="4" class="no-data">'+(q?'Aucun résultat':'Whitelist vide')+'</td></tr>';
          return;
        }
        tbody.innerHTML = filtered.map(function(w) {
          var ip = (w.ip||'').replace(/'/g,"\'");
          return '<tr>'+
            '<td><code style="color:var(--green)">'+w.ip+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(w.raison||'—')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem">'+(w.date_ajout||'').slice(0,16)+'</td>'+
            '<td>'+
              '<button class="action-btn red" data-ip="'+ip+'" onclick="FW.removeWhitelist(this.dataset.ip)" title="Supprimer de la whitelist">'+
                '<i class="fas fa-trash"></i> Supprimer'+
              '</button>'+
            '</td>'+
          '</tr>';
        }).join('');
      })
      .catch(function(e){ Toast.show('Erreur whitelist: '+e.message,'error'); });
  }

  /* ─── BLACKLIST ─────────────────────────────── */
  function loadBlacklist() {
    _api('/api/firewall/blacklist')
      .then(function(list) {
        var tbody = document.getElementById('fw-bl-tbody');
        if (!tbody) return;
        var el = document.getElementById('fw-bl');
        if (el) el.textContent = list.length;

        var q = (document.getElementById('bl-search')?.value||'').toLowerCase().trim();
        var filtered = q ? list.filter(function(b){return (b.ip||'').indexOf(q)>=0;}) : list;

        if (!filtered.length) {
          tbody.innerHTML = '<tr><td colspan="5" class="no-data">'+(q?'Aucun résultat':'Blacklist vide')+'</td></tr>';
          return;
        }
        tbody.innerHTML = filtered.map(function(b) {
          var ip = (b.ip||'').replace(/'/g,"\'");
          return '<tr>'+
            '<td><code style="color:var(--red)">'+b.ip+'</code></td>'+
            '<td style="font-size:0.72rem;color:var(--muted)">'+(b.raison||'—')+'</td>'+
            '<td style="font-size:0.7rem;color:var(--muted)">'+(b.source||'manual')+'</td>'+
            '<td style="color:var(--muted);font-size:0.65rem">'+(b.date_ajout||'').slice(0,16)+'</td>'+
            '<td style="display:flex;gap:3px">'+
              '<button class="action-btn red" data-ip="'+ip+'" onclick="FW.blockFromBL(this.dataset.ip)" title="Bloquer maintenant via nftables">'+
                '<i class="fas fa-ban"></i> Bloquer'+
              '</button>'+
              '<button class="action-btn" data-ip="'+ip+'" onclick="FW.removeBlacklist(this.dataset.ip)" title="Supprimer de la blacklist" style="color:var(--red)">'+
                '<i class="fas fa-trash"></i>'+
              '</button>'+
            '</td>'+
          '</tr>';
        }).join('');
      })
      .catch(function(e){ Toast.show('Erreur blacklist: '+e.message,'error'); });
  }

  /* ─── CONNEXIONS LIVE ───────────────────────── */
  function loadConnections() {
    var tbody = document.getElementById('fw-conn-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="8" class="no-data"><i class="fas fa-spinner fa-spin"></i> Chargement...</td></tr>';
    _api('/api/firewall/connections')
      .then(function(conns) {
        if (!conns.length) {
          tbody.innerHTML = '<tr><td colspan="8" class="no-data">Aucune connexion active</td></tr>';
          return;
        }
        tbody.innerHTML = conns.map(function(c) {
          return '<tr style="'+(c.suspicious?'background:rgba(239,68,68,0.06)':'')+'">'+
            '<td><span class="badge badge-info">'+(c.proto||'—')+'</span></td>'+
            '<td style="font-size:0.7rem;color:var(--muted)">'+(c.state||'—')+'</td>'+
            '<td><code>'+(c.local_ip||'—')+'</code></td>'+
            '<td style="font-size:0.72rem">'+(c.local_port||'—')+'</td>'+
            '<td><code style="color:'+(c.suspicious?'var(--red)':'inherit')+'">'+(c.remote_ip||'—')+'</code></td>'+
            '<td style="font-size:0.72rem">'+(c.remote_port||'—')+'</td>'+
            '<td style="font-size:0.7rem;color:var(--muted)">'+(c.process||'—')+'</td>'+
            '<td>'+(c.suspicious
              ?'<span class="badge badge-critical">SUSPECT</span>'
              :'<span class="badge badge-safe">OK</span>')+
            '</td>'+
          '</tr>';
        }).join('');
      })
      .catch(function() {
        tbody.innerHTML = '<tr><td colspan="8" class="no-data">Erreur chargement connexions</td></tr>';
      });
  }

  /* ─── LOGS ──────────────────────────────────── */
  function loadLogs() {
    _api('/api/firewall/logs?limit=50')
      .then(function(logs) {
        var tbody = document.getElementById('fw-logs-tbody');
        if (!tbody) return;
        if (!logs.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-data">Aucun log firewall</td></tr>';
          return;
        }
        tbody.innerHTML = logs.map(function(l) {
          var bl = ['BLOCK','BLOCKED'].indexOf(l.action) >= 0;
          return '<tr>'+
            '<td style="color:var(--muted);font-size:0.65rem;white-space:nowrap">'+(l.timestamp||'').slice(0,19)+'</td>'+
            '<td><span class="badge badge-'+(bl?'critical':l.action==='UNBLOCK'?'safe':'info')+'">'+(l.action||'—')+'</span></td>'+
            '<td><code style="color:'+(bl?'var(--red)':'inherit')+'">'+(l.ip_src||'—')+'</code></td>'+
            '<td><code>'+(l.ip_dst||'—')+'</code></td>'+
            '<td style="font-size:0.72rem">'+(l.port_dst||'—')+'</td>'+
            '<td><span class="badge badge-info">'+(l.protocole||'—')+'</span></td>'+
          '</tr>';
        }).join('');
      })
      .catch(function(e){ console.error('loadLogs:',e); });
  }

  /* ─── ACTIONS ───────────────────────────────── */
  function block(ip, raison) {
    if (!ip || ip==='—') { Toast.show('IP invalide','error'); return; }
    var r = raison || prompt('Raison du blocage :','Blocage manuel');
    if (r===null) return;
    _api('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison='+encodeURIComponent(r))
      .then(function(d) {
        Toast.show(d.message||d.msg||'✅ '+ip+' bloquée', d.success===false?'error':'success');
        loadBlocked();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur blocage: '+e.message,'error'); });
  }

  function unblock(ip) {
    if (!ip || ip==='—') { Toast.show('IP invalide','error'); return; }
    if (!confirm('Débloquer '+ip+' ?')) return;
    _api('/api/firewall/debloquer/'+encodeURIComponent(ip))
      .then(function(d) {
        Toast.show(d.message||d.msg||'✅ '+ip+' débloquée', d.success===false?'error':'success');
        loadBlocked();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur déblocage: '+e.message,'error'); });
  }

  function addWhitelist() {
    var inp    = document.getElementById('wl-ip-input');
    var rinp   = document.getElementById('wl-raison-input');
    var ip     = (inp?inp.value:'').trim();
    var raison = (rinp?rinp.value:'').trim() || 'Whitelist manuelle';
    if (!ip) { Toast.show('Entrez une IP','error'); if(inp) inp.focus(); return; }
    _post('/api/firewall/whitelist/add', {ip:ip, raison:raison})
      .then(function(d) {
        Toast.show(d.message||'✅ '+ip+' whitelistée', d.success===false?'error':'success');
        if (d.success !== false) {
          if (inp)  inp.value  = '';
          if (rinp) rinp.value = '';
          loadWhitelist();
          updateFirewallStats();
        }
      })
      .catch(function(e){ Toast.show('Erreur whitelist: '+e.message,'error'); });
  }

  function removeWhitelist(ip) {
    if (!confirm('Supprimer '+ip+' de la whitelist ?')) return;
    _post('/api/firewall/whitelist/'+encodeURIComponent(ip)+'/remove', {})
      .then(function(d) {
        Toast.show(d.message||'✅ Supprimé','success');
        loadWhitelist();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function addBlacklist() {
    var inp    = document.getElementById('bl-ip-input');
    var rinp   = document.getElementById('bl-raison-input');
    var ip     = (inp?inp.value:'').trim();
    var raison = (rinp?rinp.value:'').trim() || 'Blacklist manuelle';
    if (!ip) { Toast.show('Entrez une IP','error'); if(inp) inp.focus(); return; }
    _post('/api/firewall/blacklist/add', {ip:ip, raison:raison, source:'manual'})
      .then(function(d) {
        Toast.show(d.message||'✅ '+ip+' blacklistée', d.success===false?'error':'success');
        if (d.success !== false) {
          if (inp)  inp.value  = '';
          if (rinp) rinp.value = '';
          loadBlacklist();
          updateFirewallStats();
        }
      })
      .catch(function(e){ Toast.show('Erreur blacklist: '+e.message,'error'); });
  }

  function removeBlacklist(ip) {
    if (!confirm('Supprimer '+ip+' de la blacklist ?')) return;
    _post('/api/firewall/blacklist/'+encodeURIComponent(ip)+'/remove', {})
      .then(function(d) {
        Toast.show(d.message||'✅ Supprimé','success');
        loadBlacklist();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function blockFromBL(ip) {
    if (!confirm('Bloquer '+ip+' via nftables maintenant ?')) return;
    _api('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison='+encodeURIComponent('Blocage depuis blacklist'))
      .then(function(d) {
        Toast.show(d.message||'✅ '+ip+' bloquée','success');
        loadBlocked();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function toggleRule(rid, actif) {
    _post('/api/firewall/rules/'+rid+'/toggle', {actif:actif})
      .then(function(d) {
        Toast.show(d.message||'✅ Règle '+(actif?'activée':'désactivée'),'success');
        loadRules();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function deleteRule(rid) {
    if (!confirm('Supprimer cette règle nftables ?')) return;
    _post('/api/firewall/rules/'+rid+'/delete', {})
      .then(function(d) {
        Toast.show(d.message||'✅ Règle supprimée','success');
        loadRules();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function openBlockModal() {
    var ip = prompt('IP à bloquer :','');
    if (!ip || !ip.trim()) return;
    var r  = prompt('Raison :','Blocage manuel') || 'Blocage manuel';
    block(ip.trim(), r);
  }

  function openRuleModal() {
    var ip    = prompt('IP source (* = tout) :','*');
    if (ip===null) return;
    var port  = prompt('Port (vide = tout) :','') || null;
    var proto = prompt('Protocole (tcp/udp/all) :','tcp') || 'tcp';
    var type_ = prompt('Action (BLOCK/ALLOW) :','BLOCK') || 'BLOCK';
    var raison= prompt('Commentaire :','Règle manuelle') || 'Règle manuelle';
    _post('/api/firewall/rules/add', {ip:ip||'*',port:port,proto:proto,type:type_,raison:raison})
      .then(function(d) {
        Toast.show(d.message||'✅ Règle ajoutée','success');
        loadRules();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function autoResponse() {
    _post('/api/firewall/auto-response', {})
      .then(function(d) {
        Toast.show(d.message||(d.total||0)+' IPs bloquées automatiquement','success');
        loadBlocked();
        updateFirewallStats();
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  // Bloquer TOUTES les IPs de la blacklist
  function blockAllBlacklist() {
    if (!confirm('Bloquer TOUTES les IPs de la blacklist ?')) return;
    _api('/api/firewall/blacklist')
      .then(function(list) {
        var ips = list.map(function(b){return b.ip;});
        if (!ips.length) { Toast.show('Blacklist vide','info'); return; }
        var done = 0;
        ips.forEach(function(ip) {
          _api('/api/firewall/bloquer/'+encodeURIComponent(ip)+'?raison=Blocage+blacklist')
            .then(function() {
              done++;
              if (done === ips.length) {
                Toast.show(done+' IPs bloquées depuis la blacklist','success');
                loadBlocked();
                loadBlacklist();
                updateFirewallStats();
              }
            })
            .catch(function(){done++;});
        });
      })
      .catch(function(e){ Toast.show('Erreur: '+e.message,'error'); });
  }

  function searchBlocked() {
    loadBlocked(); // recharge et applique le filtre
  }
  function searchWhitelist() { loadWhitelist(); }
  function searchBlacklist() { loadBlacklist(); }
  function filterTable(tbodyId, q) {
    q = (q||'').toLowerCase().trim();
    var tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    tbody.querySelectorAll('tr').forEach(function(row) {
      row.style.display = (!q || row.textContent.toLowerCase().indexOf(q)>=0) ? '' : 'none';
    });
  }

  function init() {
    showTab('blocked');
    updateFirewallStats();
  }

  return {
    showTab:showTab, init:init,
    loadBlocked:loadBlocked, loadRules:loadRules,
    loadWhitelist:loadWhitelist, loadBlacklist:loadBlacklist,
    loadConnections:loadConnections, loadLogs:loadLogs,
    block:block, unblock:unblock,
    addWhitelist:addWhitelist, removeWhitelist:removeWhitelist,
    addBlacklist:addBlacklist, removeBlacklist:removeBlacklist,
    blockFromBL:blockFromBL, blockAllBlacklist:blockAllBlacklist,
    toggleRule:toggleRule, deleteRule:deleteRule,
    openBlockModal:openBlockModal, openRuleModal:openRuleModal,
    autoResponse:autoResponse,
    searchBlocked:searchBlocked, searchWhitelist:searchWhitelist,
    searchBlacklist:searchBlacklist, filterTable:filterTable,
  };
})();
window.FW = FW;
