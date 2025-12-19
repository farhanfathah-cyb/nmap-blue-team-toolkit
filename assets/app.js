// Nmap Blue Team Toolkit — client-side command builder + sample outputs
// This site does not perform scanning. It generates templates + learning outputs only.

import scans from './scans.json' assert { type: 'json' };

const $ = (sel) => document.querySelector(sel);

const yearEl = $('#year');
yearEl.textContent = String(new Date().getFullYear());

const targetInput = $('#targetInput');
const searchInput = $('#searchInput');
const categorySelect = $('#categorySelect');
const scanList = $('#scanList');

const optSudo = $('#optSudo');
const optOutput = $('#optOutput');
const optNoDns = $('#optNoDns');
const optPn = $('#optPn');

const optTiming = $('#optTiming');
const optRate = $('#optRate');
const optRetries = $('#optRetries');
const optTimeout = $('#optTimeout');

const selectedScanTag = $('#selectedScanTag');
const cmdOutput = $('#cmdOutput');

const sampleOutput = $('#sampleOutput');
const meaningList = $('#meaningList');
const nextStepsList = $('#nextStepsList');

const btnCopyCmd = $('#btnCopyCmd');
const btnCopyOut = $('#btnCopyOut');
const btnReset = $('#btnReset');
const btnPasteExample = $('#btnPasteExample');

const legalDialog = $('#legalDialog');
const btnLegal = $('#btnLegal');
const btnCloseLegal = $('#btnCloseLegal');

let selectedScan = null;

function sanitizeTarget(t){
  return (t || '').trim();
}

function buildCategoryOptions(){
  const cats = Array.from(new Set(scans.map(s => s.category))).sort();
  for(const c of cats){
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = c;
    categorySelect.appendChild(opt);
  }
}

function renderList(){
  const q = (searchInput.value || '').toLowerCase().trim();
  const cat = categorySelect.value;

  scanList.innerHTML = '';
  const filtered = scans.filter(s => {
    const matchesCat = (cat === 'all') ? true : s.category === cat;
    const hay = `${s.title} ${s.description} ${s.category} ${s.command}`.toLowerCase();
    const matchesQ = q ? hay.includes(q) : true;
    return matchesCat && matchesQ;
  });

  if(filtered.length === 0){
    const empty = document.createElement('div');
    empty.className = 'scan-item';
    empty.innerHTML = '<h3>No matches <span class="badge">Tip</span></h3><p class="desc">Try searching for “smb”, “tls”, “udp”, or clear filters.</p>';
    scanList.appendChild(empty);
    return;
  }

  for(const s of filtered){
    const item = document.createElement('div');
    item.className = 'scan-item';
    item.setAttribute('role','listitem');

    item.innerHTML = `
      <h3>${escapeHtml(s.title)} <span class="badge">${escapeHtml(s.category)}</span></h3>
      <p class="desc">${escapeHtml(s.description)}</p>
      <div class="example"><code>${escapeHtml(s.command.replace('{{target}}','target'))}</code></div>
    `;

    item.addEventListener('click', () => selectScan(s.id));
    scanList.appendChild(item);
  }
}

function escapeHtml(str){
  return String(str)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}

function applySafetyOptions(cmd){
  const parts = [];

  if(optTiming.checked) parts.push('-T2');
  if(optRate.checked) parts.push('--max-rate 100');
  if(optRetries.checked) parts.push('--max-retries 2');
  if(optTimeout.checked) parts.push('--host-timeout 2m');

  // General options
  if(optNoDns.checked) parts.push('-n');
  if(optPn.checked) parts.push('-Pn');

  // Outputs (defensive: help documentation)
  if(optOutput.checked){
    const ts = new Date().toISOString().replaceAll(':','').slice(0,15);
    parts.push(`-oN scan-${ts}.txt -oX scan-${ts}.xml`);
  }

  // Insert options after 'nmap'
  // 'nmap' + options + rest
  const tokens = cmd.split(' ');
  const nmapIndex = tokens.indexOf('nmap');
  if(nmapIndex !== -1){
    tokens.splice(nmapIndex + 1, 0, ...parts);
  }
  return tokens.join(' ').replaceAll('  ',' ').trim();
}

function buildCommand(scan){
  const target = sanitizeTarget(targetInput.value);
  const safeTarget = target || '<target>';
  let cmd = scan.command.replace('{{target}}', safeTarget);

  // Prefix sudo if desired
  if(optSudo.checked && !cmd.startsWith('sudo ')){
    cmd = `sudo ${cmd}`;
  }

  // Apply safety + output switches
  cmd = applySafetyOptions(cmd);

  return cmd;
}

function selectScan(id){
  selectedScan = scans.find(s => s.id === id) || null;

  if(!selectedScan){
    selectedScanTag.textContent = 'No scan selected';
    cmdOutput.textContent = 'Select a scan to generate a command…';
    sampleOutput.textContent = 'Select a scan to view a sample output…';
    meaningList.innerHTML = '';
    nextStepsList.innerHTML = '';
    return;
  }

  selectedScanTag.textContent = selectedScan.title;
  cmdOutput.textContent = buildCommand(selectedScan);

  sampleOutput.textContent = selectedScan.sample_output;

  meaningList.innerHTML = '';
  for(const m of selectedScan.meaning || []){
    const li = document.createElement('li');
    li.textContent = m;
    meaningList.appendChild(li);
  }

  nextStepsList.innerHTML = '';
  for(const n of selectedScan.next_steps || []){
    const li = document.createElement('li');
    li.textContent = n;
    nextStepsList.appendChild(li);
  }
}

function copyText(text){
  navigator.clipboard.writeText(text).then(()=>{
    toast('Copied to clipboard');
  }).catch(()=>{
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast('Copied to clipboard');
  });
}

function toast(msg){
  const t = document.createElement('div');
  t.style.position = 'fixed';
  t.style.bottom = '18px';
  t.style.left = '50%';
  t.style.transform = 'translateX(-50%)';
  t.style.background = 'rgba(0,0,0,.7)';
  t.style.border = '1px solid rgba(255,255,255,.15)';
  t.style.padding = '10px 12px';
  t.style.borderRadius = '999px';
  t.style.color = 'white';
  t.style.zIndex = 9999;
  t.style.fontSize = '13px';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 1200);
}

function resetAll(){
  targetInput.value = '';
  searchInput.value = '';
  categorySelect.value = 'all';

  optSudo.checked = false;
  optOutput.checked = false;
  optNoDns.checked = false;
  optPn.checked = false;

  optTiming.checked = false;
  optRate.checked = false;
  optRetries.checked = false;
  optTimeout.checked = false;

  selectedScan = null;
  renderList();
  selectScan(''); // clears
}

function wireEvents(){
  searchInput.addEventListener('input', renderList);
  categorySelect.addEventListener('change', renderList);

  for(const el of [targetInput,optSudo,optOutput,optNoDns,optPn,optTiming,optRate,optRetries,optTimeout]){
    el.addEventListener('input', () => {
      if(selectedScan) cmdOutput.textContent = buildCommand(selectedScan);
    });
    el.addEventListener('change', () => {
      if(selectedScan) cmdOutput.textContent = buildCommand(selectedScan);
    });
  }

  btnCopyCmd.addEventListener('click', () => {
    copyText(cmdOutput.textContent || '');
  });
  btnCopyOut.addEventListener('click', () => {
    copyText(sampleOutput.textContent || '');
  });
  btnReset.addEventListener('click', resetAll);

  btnPasteExample.addEventListener('click', () => {
    targetInput.value = '192.168.1.0/24';
    toast('Example target inserted');
    if(selectedScan) cmdOutput.textContent = buildCommand(selectedScan);
  });

  btnLegal.addEventListener('click', () => legalDialog.showModal());
  btnCloseLegal.addEventListener('click', () => legalDialog.close());
}

function init(){
  buildCategoryOptions();
  renderList();
  wireEvents();
}

init();
