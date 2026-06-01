/* reports.js — Smart NetSec SOC */
'use strict';

const Reports = (() => {

  function generate() {
    const btn = document.getElementById('btn-gen-report');
    if (btn) { btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Génération...'; }

    // Ouvrir le PDF dans un onglet + déclencher download
    window.open('/generer-rapport', '_blank');

    // Attendre puis recharger la liste
    setTimeout(() => {
      loadList();
      if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-plus"></i> Nouveau rapport'; }
      if (window.Toast) Toast.show('Rapport PDF généré !', 'success');
    }, 2000);
  }

  function loadList() {
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
          <tr class="report-row" data-date="${r.date_creation||''}">
            <td style="color:var(--text2);font-weight:600">#${r.id}</td>
            <td style="color:var(--text2);font-size:0.72rem;white-space:nowrap">${(r.date_creation||'').slice(0,19)}</td>
            <td style="font-size:0.78rem;color:var(--text2)">${r.titre||'Rapport SOC'}</td>
            <td><span class="badge badge-info"><i class="fas fa-desktop"></i> ${r.nb_appareils||0}</span></td>
            <td>
              <span class="badge ${r.score_global>=80?'badge-safe':r.score_global>=60?'badge-medium':'badge-critical'}">
                Score: ${r.score_global||0}/100
              </span>
            </td>
            <td>
              <a href="/generer-rapport" class="action-btn green" title="Télécharger PDF">
                <i class="fas fa-file-pdf"></i> PDF
              </a>
            </td>
          </tr>`).join('');
      })
      .catch(() => {});
  }

  function filterReports(type, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    const rows = document.querySelectorAll('.report-row');
    const now  = new Date();
    rows.forEach(row => {
      if (type==='all') { row.style.display=''; return; }
      const d = new Date(row.dataset.date);
      row.style.display=(!isNaN(d)&&now-d<7*86400000)?'':'none';
    });
  }

  return { generate, loadList, filterReports };
})();

window.Reports       = Reports;
window.generateReport= () => Reports.generate();
window.filterReports = (t,b) => Reports.filterReports(t,b);
