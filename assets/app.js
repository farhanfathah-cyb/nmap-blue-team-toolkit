
const BRAND = "Farhan Mohammed Fathah \u2014 Cybersecurity Enthusiast";
const PROJECT = "Nmap Blue Team Toolkit";

function qs(sel, root=document){ return root.querySelector(sel); }
function qsa(sel, root=document){ return [...root.querySelectorAll(sel)]; }

function setActiveNav(){
  const path = location.pathname.split('/').pop() || 'index.html';
  qsa('.nav a').forEach(a => {
    const href = a.getAttribute('href');
    if (href === path) a.classList.add('active');
  });
}

function loadTheme(){
  const saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
}
function toggleTheme(){
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}

function openModal(id){ qs(id).classList.add('show'); }
function closeModal(id){ qs(id).classList.remove('show'); }

function toast(msg){
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.position = 'fixed';
  el.style.bottom = '18px';
  el.style.left = '50%';
  el.style.transform = 'translateX(-50%)';
  el.style.padding = '10px 12px';
  el.style.border = '1px solid var(--border)';
  el.style.borderRadius = '14px';
  el.style.background = 'rgba(0,0,0,.6)';
  el.style.color = 'var(--text)';
  el.style.backdropFilter = 'blur(10px)';
  el.style.zIndex = '99';
  document.body.appendChild(el);
  setTimeout(()=>el.remove(), 1600);
}

function saveSelectedScan(scan){
  localStorage.setItem('selectedScan', JSON.stringify(scan));
}
function getSelectedScan(){
  try { return JSON.parse(localStorage.getItem('selectedScan') || 'null'); }
  catch(e){ return null; }
}

function copyToClipboard(text){
  navigator.clipboard.writeText(text)
    .then(()=>toast('Copied to clipboard ✅'))
    .catch(()=>toast('Copy failed'));
}

document.addEventListener('DOMContentLoaded', ()=>{
  loadTheme();
  setActiveNav();

  const themeBtn = qs('#themeBtn');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  const legalBtn = qs('#legalBtn');
  if (legalBtn) legalBtn.addEventListener('click', ()=>openModal('#legalModal'));

  const legalClose = qs('#legalClose');
  if (legalClose) legalClose.addEventListener('click', ()=>closeModal('#legalModal'));

  const backdrop = qs('#legalModal');
  if (backdrop) backdrop.addEventListener('click', (e)=>{ if (e.target === backdrop) closeModal('#legalModal'); });
});
