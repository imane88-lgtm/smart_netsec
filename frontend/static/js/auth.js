/* ══════════════════════════════════════════════
   SMART NETSEC SOC — auth.js
   Logique page authentification
══════════════════════════════════════════════ */
'use strict';

/* ══ THÈME ══ */
function initAuthTheme() {
  const t    = localStorage.getItem('netsec-theme') || 'dark';
  const icon = document.getElementById('theme-icon');
  document.documentElement.setAttribute('data-theme', t);
  if (icon) icon.className = t==='dark' ? 'fas fa-moon' : 'fas fa-sun';
}

function toggleAuthTheme() {
  const curr = localStorage.getItem('netsec-theme') || 'dark';
  const next = curr==='dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('netsec-theme', next);
  const icon = document.getElementById('theme-icon');
  if (icon) icon.className = next==='dark' ? 'fas fa-moon' : 'fas fa-sun';
}

/* ══ PASSWORD TOGGLE ══ */
function togglePwd(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  const isText = inp.type === 'text';
  inp.type = isText ? 'password' : 'text';
  const icon = btn?.querySelector('i');
  if (icon) icon.className = isText ? 'fas fa-eye' : 'fas fa-eye-slash';
}

/* ══ PASSWORD STRENGTH ══ */
function checkStrength(val) {
  const segs  = document.querySelectorAll('.strength-bar-seg');
  const label = document.getElementById('strength-text');
  if (!val) {
    segs.forEach(s => { s.style.background='var(--border)'; });
    if (label) label.textContent='';
    return;
  }
  let score = 0;
  if (val.length>=8)                    score++;
  if (/[A-Z]/.test(val))               score++;
  if (/[a-z]/.test(val))               score++;
  if (/\d/.test(val))                  score++;
  if (/[!@#$%^&*()_\-.,?]/.test(val)) score++;

  const levels = [
    {color:'#ef4444',text:'Très faible'},
    {color:'#f97316',text:'Faible'},
    {color:'#f59e0b',text:'Moyen'},
    {color:'#84cc16',text:'Bien'},
    {color:'#22c55e',text:'Fort ✓'},
  ];
  const lv = levels[score-1] || levels[0];

  segs.forEach((s, i) => {
    s.style.background = i < score ? lv.color : 'var(--border)';
    s.style.transition = 'background 0.3s';
  });
  if (label) { label.textContent=lv.text; label.style.color=lv.color; }
}

/* ══ FORM VALIDATION ══ */
function validateLogin(e) {
  const user = document.getElementById('username')?.value?.trim();
  const pwd  = document.getElementById('password')?.value;
  if (!user || !pwd) {
    e.preventDefault();
    showFormError('Veuillez remplir tous les champs.');
    return false;
  }
  const btn = document.querySelector('.btn-auth');
  if (btn) { btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Connexion...'; }
}

function showFormError(msg) {
  let box = document.getElementById('form-error');
  if (!box) {
    box = document.createElement('div');
    box.id = 'form-error';
    box.className = 'auth-alert error';
    const form = document.querySelector('form');
    if (form) form.prepend(box);
  }
  box.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${msg}`;
  box.style.display = 'flex';
}

/* ══ INIT ══ */
document.addEventListener('DOMContentLoaded', () => {
  initAuthTheme();

  // Theme button
  document.getElementById('auth-theme-btn')?.addEventListener('click', toggleAuthTheme);

  // Form submit
  document.querySelector('form')?.addEventListener('submit', validateLogin);

  // Input animation
  document.querySelectorAll('.form-input').forEach(inp => {
    inp.addEventListener('focus', () => {
      inp.closest('.input-wrap')?.querySelector('.input-icon')?.style.setProperty('color','var(--blue)');
    });
    inp.addEventListener('blur', () => {
      if (!inp.value) inp.closest('.input-wrap')?.querySelector('.input-icon')?.style.setProperty('color','var(--muted)');
    });
  });
});

window.toggleAuthTheme = toggleAuthTheme;
window.togglePwd       = togglePwd;
window.checkStrength   = checkStrength;
