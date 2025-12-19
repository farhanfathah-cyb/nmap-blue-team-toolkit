
function addHistory(entry){
  const hist = JSON.parse(localStorage.getItem('history') || '[]');
  hist.unshift(entry);
  localStorage.setItem('history', JSON.stringify(hist.slice(0,50)));
}

document.addEventListener('DOMContentLoaded', ()=>{
  const scan = getSelectedScan();
  const cmd = localStorage.getItem('finalCommand');
  if(scan && cmd){
    addHistory({ts: new Date().toISOString(), scan: scan.name, category: scan.category, command: cmd});
  }

  const hist = JSON.parse(localStorage.getItem('history') || '[]');
  const wrap = qs('#historyWrap');
  if(hist.length===0){
    wrap.innerHTML = `<div class="notice">No history yet. Generate a command in Builder and open Results.</div>`;
    return;
  }

  wrap.innerHTML = hist.map(h=>`
    <div class="scan-card" style="cursor:default">
      <div class="tagrow">
        <span class="tag cat">${h.category}</span>
        <span class="tag">${new Date(h.ts).toLocaleString()}</span>
      </div>
      <h3 style="margin-top:0">${h.scan}</h3>
      <div class="codebox">${h.command.replaceAll('<','&lt;').replaceAll('>','&gt;')}</div>
      <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
        <button class="btn btn-primary" data-cmd="${h.command.replaceAll('"','&quot;')}">Copy Command</button>
      </div>
    </div>
  `).join('');

  qsa('button[data-cmd]').forEach(b=> b.addEventListener('click', ()=>copyToClipboard(b.dataset.cmd)));

  qs('#clearHistory').addEventListener('click', ()=>{
    localStorage.removeItem('history');
    location.reload();
  });
});
