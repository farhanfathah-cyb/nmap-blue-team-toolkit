
const CATEGORY_LABELS = {
  all: "All Scans",
  discovery: "Discovery",
  baseline: "Baseline / Inventory",
  exposure: "Exposure & Risk",
  web: "Web",
  windows: "Windows",
  linux: "Linux",
  dns: "DNS",
  mail: "Mail",
  database: "Database",
  incident: "Incident Response",
  audit: "Audit / Compliance"
};

async function loadScans(){
  const res = await fetch('assets/scans.json');
  return await res.json();
}

function matches(search, scan){
  if(!search) return true;
  const s = search.toLowerCase();
  return (
    scan.name.toLowerCase().includes(s) ||
    scan.description.toLowerCase().includes(s) ||
    scan.category.toLowerCase().includes(s) ||
    (scan.tags||[]).join(' ').toLowerCase().includes(s)
  );
}

function renderCards(scans){
  const wrap = qs('#scanCards');
  wrap.innerHTML = '';
  if(scans.length === 0){
    wrap.innerHTML = `<div class="notice" style="grid-column:1/-1">
      <b>No results.</b> Try clearing search or choosing “All Scans”.
    </div>`;
    return;
  }

  scans.forEach(scan=>{
    const noiseClass = scan.noise === 'low' ? 'noise-low' : (scan.noise === 'medium' ? 'noise-med' : 'noise-high');
    const card = document.createElement('div');
    card.className = 'scan-card';
    card.tabIndex = 0;
    card.innerHTML = `
      <div class="tagrow">
        <span class="tag cat">${CATEGORY_LABELS[scan.category] || scan.category}</span>
        <span class="tag ${noiseClass}">Noise: ${scan.noise}</span>
        <span class="tag">Risk: ${scan.risk}</span>
        ${(scan.tags||[]).slice(0,3).map(t=>`<span class="tag">${t}</span>`).join('')}
      </div>
      <h3>${scan.name}</h3>
      <div class="meta">${scan.description}</div>
      <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
        <button class="btn btn-primary" data-action="load">Load → Builder</button>
        <button class="btn" data-action="preview">Preview Output</button>
      </div>
    `;

    card.addEventListener('click', (e)=>{
      const btn = e.target.closest('button');
      const action = btn && btn.dataset ? btn.dataset.action : null;
      if(action === 'preview'){ showPreview(scan); return; }
      if(action === 'load' || !action){
        saveSelectedScan(scan);
        location.href = 'builder.html';
      }
    });

    card.addEventListener('keydown', (e)=>{
      if(e.key === 'Enter'){
        saveSelectedScan(scan);
        location.href = 'builder.html';
      }
    });

    wrap.appendChild(card);
  });
}

function showPreview(scan){
  qs('#previewTitle').textContent = scan.name;
  qs('#previewCmd').textContent = scan.command;
  qs('#previewOut').textContent = scan.sample_output;
  const ul = qs('#previewNotes');
  ul.innerHTML = (scan.soc_notes||[]).map(n=>`<li>${n}</li>`).join('');
  openModal('#previewModal');
}

document.addEventListener('DOMContentLoaded', async ()=>{
  const allScans = await loadScans();

  const searchEl = qs('#scanSearch');
  const listEl = qs('#scanList');
  const catEl = qs('#categoryFilter');
  const countEl = qs('#scanCount');

  function apply(){
    const q = (searchEl.value||'').trim();
    const list = listEl.value || 'all';
    const cat = catEl.value || 'all';

    let filtered = [...allScans];
    if(list !== 'all') filtered = filtered.filter(s=>s.category === list);
    if(cat !== 'all') filtered = filtered.filter(s=>s.category === cat);
    filtered = filtered.filter(s=>matches(q, s));

    renderCards(filtered);
    countEl.textContent = `${filtered.length} scan(s)`;
  }

  [searchEl, listEl, catEl].forEach(el=>el.addEventListener('input', apply));
  apply();

  qs('#previewClose').addEventListener('click', ()=>closeModal('#previewModal'));
  const backdrop = qs('#previewModal');
  backdrop.addEventListener('click', (e)=>{ if(e.target===backdrop) closeModal('#previewModal'); });
});
