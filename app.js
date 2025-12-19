/* Nmap Blue Team Toolkit • Farhan Mohammed Fathah — Cybersecurity Enthusiast
   Built for authorized security testing and education. */

// ====== Scan Library (Blue Team Focused, Authorized Use Only) ======
const SCANS = [
  // ---------- DISCOVERY ----------
  {
    id: "discovery_ping_sweep",
    name: "Host Discovery (Ping Sweep)",
    category: "discovery",
    tags: ["discovery","hosts","inventory"],
    cmd: ["-sn"],
    details: "Find live hosts quickly (no port scan). Great for asset discovery.",
    mapping: "MITRE: T1018 • CIS: Asset Inventory",
    sample: `Nmap scan report for 10.0.0.1
Host is up (0.0040s latency).
Nmap scan report for 10.0.0.21
Host is up (0.0098s latency).

Nmap done: 256 IP addresses (2 hosts up) scanned in 3.12 seconds`,
    meaning: "Identifies live hosts only (no ports). Use it to build a target list.",
    risk: "🟢 Low — discovery only (still requires authorization).",
    next: "Confirm asset ownership, then run baseline scans on approved hosts/ranges."
  },
  {
    id: "discovery_arp_local",
    name: "LAN Discovery (ARP scan)",
    category: "discovery",
    tags: ["arp","lan","inventory"],
    cmd: ["-sn","-PR"],
    details: "Fast local subnet discovery (ARP). Best on the same LAN segment.",
    mapping: "MITRE: T1018 • CIS: Asset Inventory",
    sample: `Nmap scan report for 192.168.1.1
Host is up (0.00030s latency).
MAC Address: 2C:3A:FD:11:22:33 (Vendor)
Nmap scan report for 192.168.1.10
Host is up (0.00041s latency).
MAC Address: B8:27:EB:AA:BB:CC (Raspberry Pi Foundation)

Nmap done: 256 IP addresses (2 hosts up) scanned in 1.10 seconds`,
    meaning: "Finds local devices and reveals MAC vendors for quick classification.",
    risk: "🟢 Low — local discovery.",
    next: "Validate unknown devices and investigate rogue endpoints."
  },
  {
    id: "discovery_dns_bruteforce_training",
    name: "Subdomain Discovery (DNS brute, training)",
    category: "discovery",
    tags: ["dns","subdomain","recon"],
    cmd: ["-p 53", "--script", "dns-brute", "--reason"],
    details: "Training-oriented DNS brute (use only on authorized domains).",
    mapping: "MITRE: T1590 • CIS: DNS Monitoring",
    sample: `PORT   STATE SERVICE
53/tcp open  domain
| dns-brute:
|   Found: dev.example.com
|_  Found: vpn.example.com`,
    meaning: "Discovers common subdomains that may expose additional services.",
    risk: "🟠 Medium — generates many DNS queries; can impact logs/monitoring.",
    next: "Validate findings, ensure staging/dev hosts are not internet-exposed."
  },

  // ---------- BASELINE / PORT SCANS ----------
  {
    id: "baseline_tcp_top100",
    name: "TCP Baseline (Top 100 + Versions)",
    category: "baseline",
    tags: ["tcp","baseline","versions"],
    cmd: ["-sS","--top-ports 100","-sV","--reason"],
    details: "Fast baseline for common TCP ports with version detection.",
    mapping: "MITRE: T1046 • CIS: Inventory",
    sample: `PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1
80/tcp   open  http     nginx 1.18.0
443/tcp  open  https    nginx 1.18.0`,
    meaning: "Shows common services and versions for inventory and patching.",
    risk: "🟡 Medium — exposes attack surface; review exposure scope.",
    next: "Confirm ports are expected; patch services; restrict access where possible."
  },
  {
    id: "tcp_connect_scan",
    name: "TCP Connect Scan (-sT)",
    category: "baseline",
    tags: ["tcp","connect","no-syn"],
    cmd: ["-sT","--top-ports 200","-sV","--reason"],
    details: "Useful when SYN scan isn’t available (no raw sockets).",
    mapping: "MITRE: T1046",
    sample: `PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd
443/tcp  open  https   Apache httpd`,
    meaning: "Connect scan completes TCP handshakes; more visible in logs.",
    risk: "🟡 Medium — higher logging footprint; ensure authorization.",
    next: "Use for internal audits where logging is acceptable."
  },
  {
    id: "full_tcp_all_ports",
    name: "Full TCP Port Scan (-p-)",
    category: "exposure",
    tags: ["tcp","all-ports","exposure"],
    cmd: ["-sS","-p-","--reason"],
    details: "Finds open TCP ports across the full 1–65535 range (no version by default).",
    mapping: "MITRE: T1046 • CIS: Exposure Review",
    sample: `PORT      STATE SERVICE
22/tcp    open  ssh
8080/tcp  open  http-proxy
49152/tcp open  unknown`,
    meaning: "Reveals uncommon ports that might be missed by top-ports scans.",
    risk: "🟠 Medium — can be time-consuming; scope carefully.",
    next: "Follow up with targeted -sV on discovered ports; validate ownership."
  },
  {
    id: "targeted_ports_scan",
    name: "Targeted Ports (Custom list)",
    category: "baseline",
    tags: ["ports","targeted","fast"],
    cmd: ["-sS","-p 21,22,25,53,80,110,135,139,143,443,445,3389","-sV","--reason"],
    details: "Quick scan of a practical, high-signal port list.",
    mapping: "MITRE: T1046",
    sample: `PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH
443/tcp  open  https   nginx
445/tcp  open  microsoft-ds Windows Server`,
    meaning: "Checks typical enterprise services quickly.",
    risk: "🟡 Medium — still active scanning.",
    next: "Restrict remote admin ports (SSH/RDP/SMB) to approved networks."
  },
  {
    id: "udp_baseline_top100",
    name: "UDP Baseline (Top 100, controlled)",
    category: "baseline",
    tags: ["udp","dns","ntp","snmp"],
    cmd: ["-sU","--top-ports 100","--reason"],
    details: "Controlled UDP baseline for common infra ports.",
    mapping: "MITRE: T1046",
    sample: `PORT     STATE         SERVICE
53/udp   open          domain
123/udp  open          ntp
161/udp  open|filtered snmp`,
    meaning: "UDP results can be open|filtered; corroborate with device config/logs.",
    risk: "🟡 Medium — UDP scanning can be noisy and slow.",
    next: "Validate SNMP exposure; restrict by ACL; monitor UDP anomalies."
  },

  // ---------- SERVICE / ENUM (DEFENSIVE) ----------
  {
    id: "service_version_aggressive",
    name: "Service Enumeration (Versions + Default Scripts)",
    category: "baseline",
    tags: ["-sV","-sC","enum"],
    cmd: ["-sS","-sV","-sC","--reason"],
    details: "Combines version detection with Nmap default scripts (safe baseline).",
    mapping: "MITRE: T1046 • CIS: Secure Configuration",
    sample: `PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH
| ssh-hostkey: 
|_  2048 SHA256:...
80/tcp open  http    nginx
|_http-title: Internal Portal`,
    meaning: "Adds extra context (titles/keys) useful for inventory and auditing.",
    risk: "🟠 Medium — scripts can increase request volume; use on authorized ranges.",
    next: "Store results as baseline artifacts; compare after changes."
  },
  {
    id: "http_quick_triage",
    name: "Web Triage (Title + Headers)",
    category: "web",
    tags: ["http","headers","title"],
    cmd: ["-sV","-p 80,443","--script","http-title,http-headers","--reason"],
    details: "Fast identification of web services via headers/title.",
    mapping: "MITRE: T1046",
    sample: `80/tcp open  http
| http-title: Internal Portal
|_Requested resource was /login`,
    meaning: "Helps classify what’s running before deeper testing.",
    risk: "🟡 Medium",
    next: "Check exposure scope; confirm TLS settings and patching."
  },
  {
    id: "tls_cipher_audit",
    name: "TLS Cipher Audit (ssl-enum-ciphers)",
    category: "audit",
    tags: ["tls","cipher","audit"],
    cmd: ["-p 443","--script","ssl-enum-ciphers","--reason"],
    details: "Audits TLS protocol/ciphers for compliance and hardening.",
    mapping: "CIS: Secure Configuration",
    sample: `443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.2:
|_    ciphers: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
    meaning: "Shows supported TLS protocols and cipher suites.",
    risk: "🟠 Medium — remediate weak protocols if present.",
    next: "Disable TLSv1.0/1.1, prefer modern ciphers, enable HSTS where appropriate."
  },

  // ---------- WINDOWS ----------
  {
    id: "windows_admin_ports_audit",
    name: "Windows Admin Ports Audit (RDP/WinRM/SMB)",
    category: "windows",
    tags: ["rdp","winrm","smb","admin"],
    cmd: ["-sS","-p 445,3389,5985,5986","-sV","--reason"],
    details: "Checks common Windows remote management ports.",
    mapping: "MITRE: T1021 • CIS: Access Control",
    sample: `445/tcp open microsoft-ds
3389/tcp open ms-wbt-server
5985/tcp open http Microsoft HTTPAPI`,
    meaning: "These services are high-value and should be segmented/restricted.",
    risk: "🟠 Medium",
    next: "Restrict by VPN/ACL, enforce MFA, monitor brute-force attempts."
  },
  {
    id: "smb_security_mode",
    name: "SMB Security Mode (Signing)",
    category: "windows",
    tags: ["smb","signing","445"],
    cmd: ["-p 445","--script","smb2-security-mode,smb-os-discovery","--reason"],
    details: "Checks SMB signing and basic OS discovery.",
    mapping: "MITRE: T1135 • CIS: Secure SMB",
    sample: `445/tcp open microsoft-ds
| smb2-security-mode:
|_  Message signing enabled but not required`,
    meaning: "Signing not required can be a security gap.",
    risk: "🟠 Medium/High",
    next: "Require SMB signing, reduce SMB exposure, monitor lateral movement."
  },

  // ---------- LINUX / UNIX ----------
  {
    id: "ssh_hardening_audit",
    name: "SSH Hardening Audit (Algorithms + Hostkey)",
    category: "linux",
    tags: ["ssh","hardening","algos"],
    cmd: ["-p 22","-sV","--script","ssh2-enum-algos,ssh-hostkey","--reason"],
    details: "Audits SSH crypto algorithms and host keys.",
    mapping: "CIS: Secure Configuration",
    sample: `22/tcp open ssh
| ssh2-enum-algos:
|_  kex_algorithms: curve25519-sha256`,
    meaning: "Shows whether modern crypto is enabled.",
    risk: "🟡 Medium (depends on exposure).",
    next: "Prefer key auth, disable password auth, restrict by IP, monitor auth failures."
  },
  {
    id: "nfs_export_check",
    name: "NFS/RPC Export Check",
    category: "linux",
    tags: ["nfs","rpc","exports"],
    cmd: ["-p 111,2049","--script","rpcinfo,nfs-showmount","--reason"],
    details: "Checks NFS exports (common misconfig surface).",
    mapping: "CIS: Network Segmentation",
    sample: `2049/tcp open nfs
| nfs-showmount:
|_  /exports (everyone)`,
    meaning: "Exports open to everyone is often a serious misconfiguration.",
    risk: "🔴 High",
    next: "Restrict exports, enforce subnet ACLs, audit file permissions."
  },

  // ---------- DNS / MAIL / DB ----------
  {
    id: "dns_zone_transfer_test",
    name: "DNS Zone Transfer Test (AXFR)",
    category: "dns",
    tags: ["dns","axfr","audit"],
    cmd: ["-p 53","--script","dns-zone-transfer","--reason"],
    details: "Checks if zone transfers are allowed (misconfiguration audit).",
    mapping: "MITRE: T1590",
    sample: `53/tcp open domain
| dns-zone-transfer:
|_ Transfer failed (denied)`,
    meaning: "Denied AXFR is expected for secure DNS.",
    risk: "🟢 Low (if denied).",
    next: "If allowed in your authorized test, restrict AXFR to secondary servers only."
  },
  {
    id: "smtp_capabilities",
    name: "SMTP Capabilities (25/587)",
    category: "mail",
    tags: ["smtp","starttls","audit"],
    cmd: ["-p 25,587","-sV","--script","smtp-commands","--reason"],
    details: "Enumerates SMTP capabilities and STARTTLS support.",
    mapping: "CIS: Secure Email",
    sample: `25/tcp open smtp
|_ smtp-commands: PIPELINING SIZE STARTTLS AUTH`,
    meaning: "Validates mail server behavior and advertised security features.",
    risk: "🟡 Medium",
    next: "Ensure no open relay; enforce strong TLS; monitor for spam bursts."
  },
  {
    id: "db_exposure_common",
    name: "Database Exposure (MySQL/Postgres/MSSQL/Redis)",
    category: "database",
    tags: ["db","exposure"],
    cmd: ["-sS","-p 1433,3306,5432,6379","-sV","--reason"],
    details: "Checks common DB ports for exposure (should be segmented).",
    mapping: "CIS: Network Segmentation",
    sample: `3306/tcp open mysql MySQL 8.0
6379/tcp open redis Redis 6.2`,
    meaning: "Databases reachable from broad networks increase risk.",
    risk: "🔴 High (if reachable outside app subnets).",
    next: "Restrict to app subnets, enforce auth, rotate secrets, monitor access logs."
  },

  // ---------- PERFORMANCE / BASELINE ARTIFACTS ----------
  {
    id: "fast_scan_no_dns",
    name: "Fast Inventory (No DNS, Top 100)",
    category: "baseline",
    tags: ["fast","-n","inventory"],
    cmd: ["-sS","--top-ports 100","-n","--reason"],
    details: "Faster inventory by skipping DNS resolution.",
    mapping: "MITRE: T1046",
    sample: `Not shown: 98 closed ports
22/tcp open ssh
80/tcp open http`,
    meaning: "Quick port visibility without the overhead of DNS lookups.",
    risk: "🟡 Medium",
    next: "Use for internal ranges; add -sV after identifying key hosts."
  },
  {
    id: "save_normal_output",
    name: "Save Output (Normal + Grepable XML)",
    category: "audit",
    tags: ["output","reporting","baseline"],
    cmd: ["-sS","--top-ports 100","-sV","--reason","-oA","scan_report"],
    details: "Saves output in multiple formats for reporting and diffing.",
    mapping: "CIS: Monitoring & Logging",
    sample: `# Files created:
# scan_report.nmap
# scan_report.gnmap
# scan_report.xml`,
    meaning: "Creates artifacts for audit trails and comparisons.",
    risk: "🟢 Low",
    next: "Store outputs securely; compare with future scans to detect drift."
  },

  // ---------- LEARNING-ONLY (Defensive understanding; no runnable presets) ----------
  {
    id: "learning_null_scan",
    name: "NULL Scan (Learning)",
    category: "incident",
    tags: ["learning","stealth","tcp"],
    locked: true,
    cmd: [],
    details: "Explains how NULL-flag probes behave and what defenders should look for in logs/IDS.",
    mapping: "MITRE: T1595 (Active Scanning) • Detection: IDS/Firewall logs, abnormal TCP flags",
    sample: `Training note:\n- Some probes send TCP packets with no flags set.\n- Responses vary by OS and firewall behavior.\n\nDefender focus:\n- Alert on unusual TCP flag combinations\n- Correlate with connection attempts and scan patterns`,
    meaning: "Used in training to understand how scanners test firewall/stack behavior with unusual TCP flags.",
    risk: "🔴 High misuse potential — learning content only.",
    next: "Defenders: tune IDS signatures for unusual TCP flags; rate-limit and log drops; correlate across ports/hosts."
  },
  {
    id: "learning_xmas_scan",
    name: "XMAS Scan (Learning)",
    category: "incident",
    tags: ["learning","stealth","tcp"],
    locked: true,
    cmd: [],
    details: "Explains 'XMAS tree' style probes and defensive detections.",
    mapping: "MITRE: T1595 (Active Scanning) • Detection: IDS TCP flag anomalies",
    sample: `Training note:\n- Some probes set multiple flags at once (e.g., FIN/PSH/URG).\n\nDefender focus:\n- Flag anomalies in IDS\n- Look for sweeps across many ports\n- Confirm if source is authorized scanner`,
    meaning: "Learning concept: how abnormal TCP flag combinations can be used to infer port states.",
    risk: "🔴 High misuse potential — learning content only.",
    next: "Defenders: log and alert on abnormal flags; implement firewall rules and scan detection thresholds."
  },
  {
    id: "learning_ack_scan",
    name: "ACK Scan (Learning)",
    category: "incident",
    tags: ["learning","firewall","mapping"],
    locked: true,
    cmd: [],
    details: "Explains how ACK-based probing can be used to map firewall rules (stateful vs stateless behavior).",
    mapping: "MITRE: T1595 (Active Scanning) • Detection: firewall 'ACK without SYN' patterns",
    sample: `Training note:\n- ACK probes can help infer filtering behavior.\n\nDefender focus:\n- Alert on packets that don't match established state\n- Watch for repeated probes across ports`,
    meaning: "Learning concept: how firewall behavior can be inferred from responses to packets that don't establish sessions.",
    risk: "🔴 High misuse potential — learning content only.",
    next: "Defenders: enforce stateful inspection, drop invalid packets, and monitor for scan patterns."
  },
  {
    id: "learning_firewall_evasion",
    name: "Firewall Evasion Concepts (Learning)",
    category: "incident",
    tags: ["learning","evasion","defense"],
    locked: true,
    cmd: [],
    details: "High-level overview of common evasion ideas and how to defend (no step-by-step or runnable commands).",
    mapping: "MITRE: T1595 (Active Scanning) • Defense: segmentation, rate-limits, IDS tuning",
    sample: `Defensive checklist:\n- Enable and review firewall/IDS logs\n- Use rate limits and connection thresholds\n- Segment networks and restrict admin ports\n- Confirm scanning windows and scanner IP allowlists`,
    meaning: "Focuses on how blue teams detect and reduce evasion effectiveness.",
    risk: "🟠 Medium (conceptual).",
    next: "Define authorized scanning policy; add allowlists for sanctioned scanners; alert on out-of-policy scans."
  }
];


const el = (id) => document.getElementById(id);
const state = { selected: null };

const STORE = {
  target: "nmap_target",
  settings: "nmap_settings_v1",
  theme: "nmap_theme",
  selectedScan: "nmap_selected_scan_id",
  customArgs: "nmap_custom_args_v1"
};

function loadSettings(){ try{ return JSON.parse(localStorage.getItem(STORE.settings)||"{}"); }catch{ return {}; } }
function saveSettings(o){ localStorage.setItem(STORE.settings, JSON.stringify(o||{})); }
function getSetting(id){ const c=el(id); if(c && typeof c.checked==="boolean") return !!c.checked; const s=loadSettings(); return !!s[id]; }
function setSetting(id,v){ const s=loadSettings(); s[id]=!!v; saveSettings(s); const c=el(id); if(c && typeof c.checked==="boolean") c.checked=!!v; }
function getTarget(){ const tEl=el("target"); const live=tEl?tEl.value:""; return (live && live.trim())?live.trim():(localStorage.getItem(STORE.target)||""); }
function setTarget(v){ localStorage.setItem(STORE.target,(v||"").trim()); const tEl=el("target"); if(tEl && tEl.value!==v) tEl.value=v; }
function setSelectedScanId(id){ localStorage.setItem(STORE.selectedScan,id||""); }
function getSelectedScanId(){ return localStorage.getItem(STORE.selectedScan)||""; }
function getCustomArgs(){ return (localStorage.getItem(STORE.customArgs)||"").trim(); }
function setCustomArgs(v){ localStorage.setItem(STORE.customArgs,(v||"").trim()); const c=el("customArgs"); if(c && c.value!==v) c.value=v; }

function initTheme(){ const saved=localStorage.getItem(STORE.theme)||"dark"; document.documentElement.dataset.theme=(saved==="light")?"light":"dark"; const btn=el("themeToggle"); if(btn) btn.textContent=(document.documentElement.dataset.theme==="light")?"☀️":"🌙"; }
function toggleTheme(){ const cur=document.documentElement.dataset.theme==="light"?"light":"dark"; const nxt=cur==="light"?"dark":"light"; document.documentElement.dataset.theme=nxt; localStorage.setItem(STORE.theme,nxt); const btn=el("themeToggle"); if(btn) btn.textContent=(nxt==="light")?"☀️":"🌙"; }

function sanitizeCustomArgs(s){
  const x=(s||"").trim();
  if(!x) return "";
  const ok=/^[a-zA-Z0-9\s._,:\-/=]+$/.test(x);
  return ok ? x : "";
}

function escapeForShell(t){ const s=(t||"").trim(); if(!s) return ""; return /^[a-zA-Z0-9.\-_:\/]+$/.test(s)?s:""; }
function getSettingsFlags(){ const f=[]; if(getSetting("noDNS")) f.push("-n"); if(getSetting("treatUp")) f.push("-Pn"); if(getSetting("t2")) f.push("-T2"); if(getSetting("maxRate")) f.push("--max-rate 100"); if(getSetting("maxRetries")) f.push("--max-retries 2"); if(getSetting("hostTimeout")) f.push("--host-timeout 2m"); return f; }
function findScanById(id){ return SCANS.find(s=>s.id===id)||null; }

function buildCommand(scan){
  if(!scan) return "Select a scan to generate a command…";
const target=escapeForShell(getTarget());
  if(!target) return "Enter a valid target (letters/numbers/dot/dash/CIDR) to generate a safe command…";
  const parts=[];
  if(getSetting("useSudo")) parts.push("sudo");
  parts.push("nmap");
  parts.push(...(scan.cmd||[]));
  parts.push(...getSettingsFlags());
  const ca = sanitizeCustomArgs(getCustomArgs());
  if(ca) parts.push(...ca.split(/\s+/));
  parts.push(target);
  return parts.join(" ");
}

async function copyText(text){
  try{ await navigator.clipboard.writeText(text); }
  catch{ const ta=document.createElement("textarea"); ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
}

const HIST_KEY="nmap_blue_team_history_v1";
function loadHistory(){ try{ return JSON.parse(localStorage.getItem(HIST_KEY)||"[]"); }catch{ return []; } }
function saveHistory(list){ localStorage.setItem(HIST_KEY, JSON.stringify(list)); }

function renderSelected(scan){
  state.selected=scan;
  if(!scan) return;
  setSelectedScanId(scan.id);

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

function getFilteredScans(){
  const q=(el("search")?el("search").value:"").trim().toLowerCase();
  const cat=(el("category")?el("category").value:"all");
  return SCANS.filter(s=>((cat==="all")||(s.category===cat)) && (!q || ((s.name+" "+(s.tags||[]).join(" ")).toLowerCase().includes(q))));
}

function renderList(){
  const items=getFilteredScans();

  if(el("scanSelect")){
    const current = (state.selected?state.selected.id:getSelectedScanId());
    el("scanSelect").innerHTML = '<option value="">Select a scan…</option>' + items.map(s=>`<option value="${s.id}">${s.name} (${s.category})</option>`).join("");
    if(current && items.some(s=>s.id===current)) el("scanSelect").value=current;
  }

  const listEl=el("scanCards");
  if(listEl){
    if(!items.length) listEl.innerHTML = '<div class="empty">No scans match this filter. Try <b>All categories</b> or clear the search box.</div>';
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
  }

  if(el("scanCount")) el("scanCount").textContent = "Scans loaded: " + items.length;
}



function renderHistory(){
  const histEl = el("history");
  if(!histEl) return;
  const list = loadHistory();
  if(!list.length){
    histEl.innerHTML = "<p class='muted'>No commands saved yet.</p>";
    return;
  }
  histEl.innerHTML = list.slice().reverse().map(item => `
    <div class="card mt">
      <b>${item.scanName}</b>
      <div class="muted">${new Date(item.ts).toLocaleString()}</div>
      <div class="muted">Target: ${item.target || "-"}</div>
      <code>${item.command}</code>
    </div>
  `).join("");
}
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

  if(el("themeToggle")) el("themeToggle").onclick=toggleTheme;

  // nav active
  const key=document.body?.dataset?.page;
  if(key) document.querySelectorAll(".nav a").forEach(a=>{ if(a.dataset.nav===key) a.classList.add("active"); });

  // hydrate target
  const tEl=el("target");
  if(tEl){ tEl.value=getTarget(); tEl.addEventListener("input",()=>setTarget(tEl.value)); tEl.addEventListener("change",()=>setTarget(tEl.value)); }
  const caEl=el("customArgs");
  const refreshCmd = () => { const scan = state.selected || findScanById(getSelectedScanId()); if(scan && el("cmd")) el("cmd").textContent = buildCommand(scan); };
  if(caEl){ caEl.value=getCustomArgs(); caEl.addEventListener("input",()=>{ setCustomArgs(caEl.value); refreshCmd(); }); caEl.addEventListener("change",()=>{ setCustomArgs(caEl.value); refreshCmd(); }); }

  // settings
  ["useSudo","saveOutputs","noDNS","treatUp","t2","maxRate","maxRetries","hostTimeout"].forEach(id=>{ const c=el(id); if(!c) return; c.checked=getSetting(id); c.onchange=()=>setSetting(id,c.checked); });

  if(el("search")) el("search").oninput=renderList;
  if(el("category")) el("category").onchange=renderList;
  if(el("scanSelect")) el("scanSelect").onchange=()=>{ const id=el("scanSelect").value; if(!id) return; const scan=findScanById(id); if(scan) renderSelected(scan); };

  if(el("copyCmd")) el("copyCmd").onclick=()=>copyText(el("cmd").textContent||"");
  if(el("copyOut")) el("copyOut").onclick=async()=>{ await copyText(el("out").textContent||""); maybeSaveOutput(); renderHistory(); };
  if(el("clearHistory")) el("clearHistory").onclick=()=>{ localStorage.removeItem(HIST_KEY); renderHistory(); };
  if(el("exportTxt")) el("exportTxt").onclick=exportHistoryTxt;
  if(el("exportCsv")) el("exportCsv").onclick=exportHistoryCsv;

  const selectedId=getSelectedScanId();
  const scan=selectedId?findScanById(selectedId):null;
  if(scan && (el("selectedScan")||el("cmd")||el("out"))) renderSelected(scan);

  if(el("scanCards")) renderList();
  if(el("history")) renderHistory();
  if(el("dashCount")) el("dashCount").textContent="Scans available: "+SCANS.length;
}

initTheme();
document.addEventListener("DOMContentLoaded", bind);


function maybeSaveCommand(){
  if(!state.selected) return;
  const entry = {
    ts: Date.now(),
    scanId: state.selected.id,
    scanName: state.selected.name,
    target: getTarget(),
    command: el("cmd") ? el("cmd").textContent : ""
  };
  const list = loadHistory();
  list.push(entry);
  saveHistory(list);
}

function downloadTextFile(filename, content){
  const blob = new Blob([content], {type: "text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 500);
}
function downloadCsvFile(filename, rows){
  const esc = (v) => {
    const s = String(v ?? "");
    if (/[",\n]/.test(s)) return '"' + s.replace(/"/g,'""') + '"';
    return s;
  };
  const csv = rows.map(r => r.map(esc).join(",")).join("\n");
  downloadTextFile(filename, csv);
}
function exportHistoryTxt(){
  const list = loadHistory();
  if(!list.length) return alert("No commands saved yet.");
  const lines = list.map(x => {
    const ts = new Date(x.ts).toISOString();
    return `[${ts}] ${x.scanName} | target=${x.target||"-"}\n${x.command}\n`;
  }).join("\n");
  downloadTextFile("nmap_toolkit_history.txt", lines);
}
function exportHistoryCsv(){
  const list = loadHistory();
  if(!list.length) return alert("No commands saved yet.");
  const rows = [["timestamp","scanName","target","command"]];
  list.forEach(x => rows.push([new Date(x.ts).toISOString(), x.scanName, x.target||"", x.command]));
  downloadCsvFile("nmap_toolkit_history.csv", rows);
}
