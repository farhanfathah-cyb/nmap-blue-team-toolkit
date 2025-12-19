const SCANS=[{id:"discovery_ping_sweep",name:"Host Discovery (Ping Sweep)",category:"discovery",tags:["discovery"],cmd:["-sn"],details:"Find live hosts quickly",mapping:"MITRE: T1018",sample:"Host is up",meaning:"Asset discovery",risk:"🟢 Low",next:"Baseline scan"}];

const el = (id) => document.getElementById(id);
const state = { selected: null };
const STORE = { target:"nmap_target", settings:"nmap_settings_v1", theme:"nmap_theme", selectedScan:"nmap_selected_scan_id" };

function loadSettings(){ try{ return JSON.parse(localStorage.getItem(STORE.settings)||"{}"); }catch{ return {}; } }
function saveSettings(o){ localStorage.setItem(STORE.settings, JSON.stringify(o||{})); }
function getSetting(id){ const c=el(id); if(c && typeof c.checked==="boolean") return !!c.checked; const s=loadSettings(); return !!s[id]; }
function setSetting(id,v){ const s=loadSettings(); s[id]=!!v; saveSettings(s); const c=el(id); if(c && typeof c.checked==="boolean") c.checked=!!v; }
function getTarget(){ const tEl=el("target"); const live=tEl?tEl.value:""; return (live && live.trim())?live.trim():(localStorage.getItem(STORE.target)||""); }
function setTarget(v){ localStorage.setItem(STORE.target,(v||"").trim()); const tEl=el("target"); if(tEl && tEl.value!==v) tEl.value=v; }
function setSelectedScanId(id){ localStorage.setItem(STORE.selectedScan,id||""); }
function getSelectedScanId(){ return localStorage.getItem(STORE.selectedScan)||""; }
function initTheme(){ const saved=localStorage.getItem(STORE.theme)||"dark"; document.documentElement.dataset.theme=(saved==="light")?"light":"dark"; const btn=el("themeToggle"); if(btn) btn.textContent=(document.documentElement.dataset.theme==="light")?"☀️":"🌙"; }
function toggleTheme(){ const cur=document.documentElement.dataset.theme==="light"?"light":"dark"; const nxt=cur==="light"?"dark":"light"; document.documentElement.dataset.theme=nxt; localStorage.setItem(STORE.theme,nxt); const btn=el("themeToggle"); if(btn) btn.textContent=(nxt==="light")?"☀️":"🌙"; }
function escapeForShell(t){ const s=(t||"").trim(); if(!s) return ""; return /^[a-zA-Z0-9.\-_:\/]+$/.test(s)?s:""; }
function getSettingsFlags(){ const f=[]; if(getSetting("noDNS")) f.push("-n"); if(getSetting("treatUp")) f.push("-Pn"); if(getSetting("t2")) f.push("-T2"); if(getSetting("maxRate")) f.push("--max-rate 100"); if(getSetting("maxRetries")) f.push("--max-retries 2"); if(getSetting("hostTimeout")) f.push("--host-timeout 2m"); return f; }
function findScanById(id){ return SCANS.find(s=>s.id===id)||null; }
function buildCommand(scan){ if(!scan) return "Select a scan to generate a command…"; if(scan.locked) return "⚠️ This scan is learning-only. No runnable preset is generated."; const target=escapeForShell(getTarget()); if(!target) return "Enter a valid target to generate a safe command…"; const parts=[]; if(getSetting("useSudo")) parts.push("sudo"); parts.push("nmap"); parts.push(...(scan.cmd||[])); parts.push(...getSettingsFlags()); parts.push(target); return parts.join(" "); }

async function copyText(text){ try{ await navigator.clipboard.writeText(text); }catch{ const ta=document.createElement("textarea"); ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); } }

const HIST_KEY="nmap_blue_team_history_v1";
function loadHistory(){ try{ return JSON.parse(localStorage.getItem(HIST_KEY)||"[]"); }catch{ return []; } }
function saveHistory(list){ localStorage.setItem(HIST_KEY, JSON.stringify(list)); }

function renderSelected(scan){ state.selected=scan; if(!scan) return; setSelectedScanId(scan.id);
  if(el("selectedScan")) el("selectedScan").textContent = scan.name + "  •  " + scan.category.toUpperCase();
  if(el("scanDetails")) el("scanDetails").textContent = (scan.details||"") + (scan.locked?"\n\n[Learning-only] No runnable preset.":"");
  if(el("mapping")) el("mapping").textContent = scan.mapping||"";
  if(el("cmd")) el("cmd").textContent = buildCommand(scan);
  if(el("out")) el("out").textContent = scan.sample||"";
  if(el("meaning")) el("meaning").textContent = scan.meaning||"—";
  if(el("risk")) el("risk").textContent = scan.risk||"—";
  if(el("next")) el("next").textContent = scan.next||"—";
  if(el("scanSelect")) el("scanSelect").value = scan.id;
}

function getFilteredScans(){ const q=(el("search")?el("search").value:"").trim().toLowerCase(); const cat=(el("category")?el("category").value:"all");
  return SCANS.filter(s=>((cat==="all")||(s.category===cat)) && (!q || ((s.name+" "+(s.tags||[]).join(" ")).toLowerCase().includes(q))));
}

function renderList(){ const items=getFilteredScans();
  if(el("scanSelect")){
    const current = (state.selected?state.selected.id:getSelectedScanId());
    el("scanSelect").innerHTML = '<option value="">Select a scan…</option>' + items.map(s=>`<option value="${s.id}">${s.name} (${s.category})</option>`).join("");
    if(current && items.some(s=>s.id===current)) el("scanSelect").value=current;
  }
  const listEl=el("scanCards");
  if(!listEl) return;
  if(!items.length) listEl.innerHTML = '<div class="empty">No scans match this filter. Try All categories or clear search.</div>';
  else listEl.innerHTML = items.map(s=>`
    <div class="scan" data-id="${s.id}">
      <div class="title">${s.name}</div>
      <div class="meta">
        <div><b>Category:</b> ${s.category}</div>
        <div><b>Tags:</b> ${(s.tags||[]).join(", ")}</div>
        <div><b>Risk:</b> ${s.risk||"—"}</div>
      </div>
    </div>`).join("");
  document.querySelectorAll(".scan").forEach(card=>card.addEventListener("click",()=>{ const scan=findScanById(card.dataset.id); if(scan) renderSelected(scan); }));
  if(el("scanCount")) el("scanCount").textContent = "Scans loaded: " + items.length;
}

function maybeSaveOutput(){ if(!getSetting("saveOutputs")) return; const scan=state.selected||findScanById(getSelectedScanId()); if(!scan) return;
  const entry={ts:Date.now(),scanId:scan.id,scanName:scan.name,target:escapeForShell(getTarget()),command:(el("cmd")?el("cmd").textContent:buildCommand(scan)),output:(el("out")?el("out").textContent:(scan.sample||""))};
  const list=loadHistory(); list.push(entry); saveHistory(list);
}

function renderHistory(){ const histEl=el("history"); const diffEl=el("diff"); if(!histEl || !diffEl) return;
  const list=loadHistory(); if(!list.length){ histEl.textContent="No saved outputs yet."; diffEl.textContent="—"; return; }
  histEl.innerHTML = list.slice().reverse().map(item=>`
    <div style="border-bottom:1px solid var(--border); padding:10px 0;">
      <div><b>${item.scanName}</b> <span class="muted">• ${new Date(item.ts).toLocaleString()}</span></div>
      <div class="muted" style="margin-top:6px;"><b>Target:</b> ${item.target||"(not set)"}</div>
      <div class="muted"><b>Command:</b> <code>${item.command}</code></div>
    </div>`).join("");
  if(list.length<2){ diffEl.textContent="Save one more output to compare."; return; }
  const a=list[list.length-2].output.split("\n"); const b=list[list.length-1].output.split("\n");
  const aSet=new Set(a), bSet=new Set(b);
  const removed=a.filter(l=>l.trim() && !bSet.has(l)).slice(0,25);
  const added=b.filter(l=>l.trim() && !aSet.has(l)).slice(0,25);
  let out=""; removed.forEach(l=>out+=`- ${l}\n`); added.forEach(l=>out+=`+ ${l}\n`);
  diffEl.textContent=out.trim()||"(No obvious line changes detected)";
}

function bind(){ 
  // modal
  const modal=el("modal"); const openLegal=el("openLegal"); const closeLegal=el("closeLegal");
  if(openLegal && modal) openLegal.onclick=()=>modal.classList.remove("hidden");
  if(closeLegal && modal) closeLegal.onclick=()=>modal.classList.add("hidden");
  if(modal) modal.addEventListener("click",e=>{ if(e.target.id==="modal") modal.classList.add("hidden"); });
  // theme
  if(el("themeToggle")) el("themeToggle").onclick=toggleTheme;

  // nav active
  const key=document.body?.dataset?.page;
  if(key) document.querySelectorAll(".nav a").forEach(a=>{ if(a.dataset.nav===key) a.classList.add("active"); });

  // hydrate
  const tEl=el("target");
  if(tEl){ tEl.value=getTarget(); tEl.addEventListener("input",()=>setTarget(tEl.value)); tEl.addEventListener("change",()=>setTarget(tEl.value)); }
  ["useSudo","saveOutputs","noDNS","treatUp","t2","maxRate","maxRetries","hostTimeout"].forEach(id=>{ const c=el(id); if(!c) return; c.checked=getSetting(id); c.onchange=()=>setSetting(id,c.checked); });

  if(el("search")) el("search").oninput=renderList;
  if(el("category")) el("category").onchange=renderList;
  if(el("scanSelect")) el("scanSelect").onchange=()=>{ const id=el("scanSelect").value; if(!id) return; const scan=findScanById(id); if(scan) renderSelected(scan); };
  if(el("copyCmd")) el("copyCmd").onclick=()=>copyText(el("cmd").textContent||"");
  if(el("copyOut")) el("copyOut").onclick=async()=>{ await copyText(el("out").textContent||""); maybeSaveOutput(); renderHistory(); };
  if(el("clearHistory")) el("clearHistory").onclick=()=>{ localStorage.removeItem(HIST_KEY); renderHistory(); };

  const selectedId=getSelectedScanId(); const scan=selectedId?findScanById(selectedId):null;
  if(scan && (el("selectedScan")||el("cmd")||el("out"))) renderSelected(scan);

  if(el("scanCards")) renderList();
  if(el("history")) renderHistory();
  if(el("dashCount")) el("dashCount").textContent="Scans available: "+SCANS.length;
}

initTheme();
document.addEventListener("DOMContentLoaded", bind);
