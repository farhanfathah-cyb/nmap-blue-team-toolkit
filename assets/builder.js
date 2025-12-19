
function fillFromSelected(){
  const scan = getSelectedScan();
  if(!scan){
    qs('#builderNotice').innerHTML = `<div class="notice"><b>No scan selected.</b> Go to <a href="scans.html">Scan Library</a> and pick one.</div>`;
    return;
  }
  qs('#scanName').textContent = scan.name;
  qs('#scanDesc').textContent = scan.description;
  qs('#scanTag').textContent = scan.category;
  qs('#cmdTemplate').value = scan.command;
  qs('#sampleOut').textContent = scan.sample_output;
  const ul = qs('#socNotes');
  ul.innerHTML = (scan.soc_notes||[]).map(n=>`<li>${n}</li>`).join('');
}

function buildCommand(){
  const tmpl = qs('#cmdTemplate').value;
  const target = (qs('#targetInput').value || '').trim() || '{TARGET}';
  const domain = (qs('#domainInput').value || '').trim() || '{DOMAIN}';
  const cmd = tmpl.split('{TARGET}').join(target).split('{DOMAIN}').join(domain);
  qs('#finalCmd').textContent = cmd;
  localStorage.setItem('finalCommand', cmd);
  return cmd;
}

document.addEventListener('DOMContentLoaded', ()=>{
  fillFromSelected();

  const saved = localStorage.getItem('defaultTarget') || '';
  if(saved && qs('#targetInput').value.trim()==='') qs('#targetInput').value = saved;

  qs('#buildBtn').addEventListener('click', ()=>buildCommand());
  qs('#copyBtn').addEventListener('click', ()=>{
    const cmd = buildCommand();
    copyToClipboard(cmd);
  });
  qs('#toResultsBtn').addEventListener('click', ()=>{
    buildCommand();
    location.href = 'results.html';
  });

  ['input','change'].forEach(evt=>{
    qs('#targetInput').addEventListener(evt, buildCommand);
    qs('#domainInput').addEventListener(evt, buildCommand);
    qs('#cmdTemplate').addEventListener(evt, buildCommand);
  });

  buildCommand();
});
