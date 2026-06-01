/* ai.js — Smart NetSec SOC */
'use strict';

const AI = (() => {
  let isOpen = false;

  function appendMsg(boxId, text, who, isErr) {
    const box = document.getElementById(boxId);
    if (!box) return;
    const row = document.createElement('div');
    row.className = who==='ai' ? 'ai-row' : 'ai-usr';
    const bub = document.createElement('div');
    bub.className = (who==='ai'?'ai-bub ai-bub-bot':'ai-bub ai-bub-usr') + (isErr?' error':'');
    bub.textContent = text;
    row.appendChild(bub);
    box.appendChild(row);
    requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
  }

  function appendTyping(boxId) {
    const box = document.getElementById(boxId);
    if (!box) return null;
    const id  = 'typ-' + Date.now();
    const row = document.createElement('div');
    row.id = id; row.className = 'ai-row';
    row.innerHTML = '<div class="ai-bub ai-bub-bot"><div class="ai-typing-wrap"><span></span><span></span><span></span></div></div>';
    box.appendChild(row);
    box.scrollTop = box.scrollHeight;
    return id;
  }

  function rmTyping(id) { document.getElementById(id)?.remove(); }

  function chat(boxId, msg) {
    if (!msg.trim()) return;
    appendMsg(boxId, msg, 'user');
    const tid = appendTyping(boxId);
    fetch('/ai/chat', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({message: msg}),
    })
    .then(r => { if(!r.ok) throw new Error(r.status); return r.json(); })
    .then(d => { rmTyping(tid); appendMsg(boxId, d.reponse||'…', 'ai'); })
    .catch(() => { rmTyping(tid); appendMsg(boxId, 'Erreur de connexion.', 'ai', true); });
  }

  function loadSysBar() {
    fetch('/ai/resume')
      .then(r => r.json())
      .then(d => {
        const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
        set('aisb-score',(d.score||0)+'/100');
        set('aisb-dev',  d.nb_appareils||0);
        set('aisb-crit', d.nb_critical||0);
        set('aisb-blk',  d.nb_bloques||0);
      })
      .catch(() => {});
  }

  function toggle() {
    isOpen = !isOpen;
    const panel = document.getElementById('ai-panel');
    if (!panel) return;
    panel.classList.toggle('open', isOpen);
    if (isOpen) {
      loadSysBar();
      setTimeout(() => document.getElementById('ai-in')?.focus(), 350);
    }
  }

  function send() {
    const inp = document.getElementById('ai-in');
    if (!inp) return;
    const msg = inp.value.trim();
    if (!msg) return;
    inp.value = '';
    chat('ai-msgs', msg);
  }

  function quick(q) {
    const inp = document.getElementById('ai-in');
    if (inp) { inp.value=q; send(); }
  }

  function pageSend() {
    const inp = document.getElementById('ai-in-page');
    if (!inp) return;
    const msg = inp.value.trim();
    if (!msg) return;
    inp.value = '';
    chat('ai-msgs-page', msg);
  }

  function pageQuick(q) {
    const inp = document.getElementById('ai-in-page');
    if (inp) { inp.value=q; pageSend(); }
  }

  function init() {
    document.getElementById('ai-in')?.addEventListener('keydown', e => {
      if (e.key==='Enter') send();
    });
    document.getElementById('ai-in-page')?.addEventListener('keydown', e => {
      if (e.key==='Enter') pageSend();
    });
  }

  return { toggle, send, quick, pageSend, pageQuick, init, loadSysBar };
})();

document.addEventListener('DOMContentLoaded', () => AI.init());

window.AI        = AI;
window.toggleAI  = () => AI.toggle();
window.aiSend    = () => AI.send();
window.aiQ       = (q) => AI.quick(q);
window.aiPageSend= () => AI.pageSend();
window.aiPageQ   = (q) => AI.pageQuick(q);
