
document.addEventListener('DOMContentLoaded', ()=>{
  const scan = getSelectedScan();
  const cmd = localStorage.getItem('finalCommand') || (scan ? scan.command : '');
  qs('#resScanName').textContent = scan ? scan.name : 'No scan selected';
  qs('#resCmd').textContent = cmd || '—';
  qs('#copyResCmd').addEventListener('click', ()=>copyToClipboard(cmd||''));

  if(scan){
    qs('#resSampleOut').textContent = scan.sample_output;
    qs('#resNotes').innerHTML = (scan.soc_notes||[]).map(n=>`<li>${n}</li>`).join('');
  } else {
    qs('#resSampleOut').textContent = 'Go to Scan Library and select a scan first.';
    qs('#resNotes').innerHTML = '';
  }
});
