// ====== Scan Library (Blue Team Focused, Authorized Use Only) ======
const SCANS = [
  // ---------- BASELINE ----------
  {
    id: "baseline_tcp_top100",
    name: "Baseline TCP (Top 100 ports)",
    category: "baseline",
    tags: ["baseline", "tcp", "inventory"],
    cmd: ["-sS", "--top-ports 100", "-sV", "--reason"],
    details: "Good first look: common services + versions (defensive inventory).",
    mapping: "MITRE: T1046 (Network Service Discovery) • CIS: Inventory & Control of Enterprise Assets",
    sample: `Starting Nmap 7.94 ( https://nmap.org ) at 2025-12-19 22:30 GST
Nmap scan report for 192.168.1.10
Host is up (0.012s latency).
Not shown: 97 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
443/tcp  open  https    nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 6.45 seconds`,
    meaning: "This host exposes SSH + web services. Version detection suggests an Ubuntu Linux server.",
    risk: "🟡 Medium — exposed services increase attack surface; validate whether these ports should be public.",
    next: "Confirm asset owner, check firewall rules, review SSH logs, validate web server patch level."
  },
  {
    id: "baseline_udp_top50",
    name: "Baseline UDP (Top 50 ports, controlled)",
    category: "baseline",
    tags: ["udp", "baseline", "dns", "ntp", "snmp"],
    cmd: ["-sU", "--top-ports 50", "--reason"],
    details: "Controlled UDP baseline for common infrastructure ports (DNS/NTP/SNMP).",
    mapping: "MITRE: T1046 • CIS: Asset Inventory & Monitoring",
    sample: `Nmap scan report for 192.168.1.1
Host is up (0.0030s latency).
PORT     STATE         SERVICE
53/udp   open          domain
123/udp  open          ntp
161/udp  open|filtered snmp
1900/udp open|filtered upnp

Nmap done: 1 IP address (1 host up) scanned in 27.11 seconds`,
    meaning: "Core infrastructure services are reachable over UDP; SNMP appears filtered/partially reachable.",
    risk: "🟡 Medium — SNMP exposure can leak sensitive device info if misconfigured.",
    next: "Verify SNMP is restricted (ACLs), confirm NTP/DNS are expected, and monitor for unusual UDP traffic."
  },
  {
    id: "baseline_os_guess",
    name: "Baseline OS Guess (Controlled)",
    category: "baseline",
    tags: ["os", "fingerprint", "inventory"],
    cmd: ["-sS", "--top-ports 50", "-O", "--osscan-limit", "--reason"],
    details: "Basic OS guess for inventory (works best when multiple ports are open).",
    mapping: "MITRE: T1046 • CIS: Asset Inventory",
    sample: `Nmap scan report for 10.0.0.20
Host is up (0.009s latency).
PORT    STATE SERVICE
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

OS details: Linux 5.4 - 5.15, or Windows Server (mixed signals)
Network Distance: 1 hop`,
    meaning: "OS guess is inconclusive due to limited signals; could be Linux with SMB or a gateway device.",
    risk: "🟢 Low — informational; avoid over-trusting OS guesses.",
    next: "Run service/version detection and correlate with CMDB/EDR to confirm OS."
  },

  // ---------- DISCOVERY ----------
  {
    id: "discovery_ping_sweep",
    name: "Asset Discovery (Ping Sweep)",
    category: "discovery",
    tags: ["discovery", "hosts", "inventory"],
    cmd: ["-sn"],
    details: "Find live hosts quickly (no port scan). Great for asset discovery.",
    mapping: "MITRE: T1018 (Remote System Discovery) • CIS: Inventory of Enterprise Assets",
    sample: `Starting Nmap 7.94 ( https://nmap.org ) at 2025-12-19 22:31 GST
Nmap scan report for 10.0.0.1
Host is up (0.0040s latency).
Nmap scan report for 10.0.0.7
Host is up (0.0061s latency).
Nmap scan report for 10.0.0.21
Host is up (0.0098s latency).

Nmap done: 256 IP addresses (3 hosts up) scanned in 3.12 seconds`,
    meaning: "Multiple live hosts responded. This helps you build an asset list for further triage.",
    risk: "🟢 Low — discovery only, but still requires authorization.",
    next: "Tag assets in CMDB, then run a baseline TCP scan on only approved ranges."
  },
  {
    id: "discovery_arp_local",
    name: "LAN Discovery (ARP scan)",
    category: "discovery",
    tags: ["arp", "lan", "inventory"],
    cmd: ["-sn", "-PR"],
    details: "Fast local subnet discovery (ARP). Best for same LAN segments.",
    mapping: "MITRE: T1018 • CIS: Asset Inventory",
    sample: `Nmap scan report for 192.168.1.1
Host is up (0.00030s latency).
MAC Address: 2C:3A:FD:11:22:33 (Vendor)
Nmap scan report for 192.168.1.10
Host is up (0.00041s latency).
MAC Address: B8:27:EB:AA:BB:CC (Raspberry Pi Foundation)

Nmap done: 256 IP addresses (2 hosts up) scanned in 1.10 seconds`,
    meaning: "ARP discovery identified live devices and MAC vendors — helpful for asset classification.",
    risk: "🟢 Low — local discovery.",
    next: "Validate unknown vendors/devices and isolate rogue endpoints if detected."
  },

  // ---------- EXPOSURE / AUDIT ----------
  {
    id: "exposure_all_ports_slow",
    name: "Exposure Check (All TCP ports, controlled)",
    category: "exposure",
    tags: ["exposure", "audit", "tcp", "all ports"],
    cmd: ["-sS", "-p-", "-sV", "--reason"],
    details: "Find unexpected services on uncommon ports (controlled, defensive).",
    mapping: "MITRE: T1046 • CIS: Continuous Vulnerability Management",
    sample: `Starting Nmap 7.94 ( https://nmap.org ) at 2025-12-19 22:32 GST
Nmap scan report for 192.168.1.25
Host is up (0.010s latency).
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.9
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8080/tcp open  http-proxy   Squid http proxy 4.10
4444/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 58.20 seconds`,
    meaning: "RDP and proxy services are exposed. Port 4444 is unusual and may indicate a custom service/backdoor.",
    risk: "🔴 High — unexpected services + uncommon port. Treat as suspicious until verified.",
    next: "Check EDR alerts, review firewall/NAT changes, inspect listening processes, and confirm if 4444 is authorized."
  },
  {
    id: "audit_tls_versions",
    name: "TLS Exposure (443) – Quick Audit",
    category: "audit",
    tags: ["tls", "https", "audit"],
    cmd: ["-p 443", "--script", "ssl-enum-ciphers", "--reason"],
    details: "Quick TLS audit (ciphers/protocols). Useful for compliance checks.",
    mapping: "CIS: Secure Configuration • SOC: Crypto Hygiene",
    sample: `PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|_      (deprecated) ...
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
|_      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
    meaning: "Server still supports older TLS versions. Modern TLSv1.2 ciphers are present.",
    risk: "🟠 Medium — older protocols may violate policy and increase risk.",
    next: "Disable TLSv1.0/1.1, confirm strong cipher suites, validate certificate chain and HSTS."
  },
  {
    id: "audit_risky_admin_ports",
    name: "Admin Ports Audit (RDP/WinRM/SSH)",
    category: "audit",
    tags: ["rdp", "winrm", "ssh", "admin"],
    cmd: ["-sS", "-p 22,3389,5985,5986", "-sV", "--reason"],
    details: "Quick check for common admin/remote management ports.",
    mapping: "MITRE: T1021 (Remote Services) • CIS: Access Control",
    sample: `Nmap scan report for 10.0.0.88
Host is up (0.006s latency).
PORT     STATE SERVICE     VERSION
22/tcp   closed ssh
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Nmap done: 1 IP address (1 host up) scanned in 4.92 seconds`,
    meaning: "RDP and WinRM are accessible — typical for managed Windows, but confirm exposure scope.",
    risk: "🟠 Medium — remote admin services are high value targets.",
    next: "Restrict by VPN/ACL, enforce MFA, monitor authentication logs and brute-force attempts."
  },

  // ---------- WEB ----------
  {
    id: "web_http_headers",
    name: "Web Quick Check (HTTP headers + title)",
    category: "web",
    tags: ["web", "http", "headers"],
    cmd: ["-sV", "-p 80,443", "--script", "http-headers,http-title", "--reason"],
    details: "Fast web triage: title + headers for quick identification.",
    mapping: "MITRE: T1046 • CIS: Secure Configuration",
    sample: `Nmap scan report for web.internal
Host is up (0.015s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.18.0
| http-title: Internal Portal
|_Requested resource was /login
| http-headers:
|   server: nginx
|   x-frame-options: SAMEORIGIN
|   content-security-policy: default-src 'self'
|_  strict-transport-security: max-age=31536000; includeSubDomains

443/tcp open  https    nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned in 8.02 seconds`,
    meaning: "Web portal identified. Security headers look partially configured (HSTS + CSP present).",
    risk: "🟡 Medium — verify TLS config, patching, and exposure scope.",
    next: "Confirm if portal should be internal only, review WAF/logs, check vulnerability scan results."
  },
  {
    id: "web_common_vuln_scripts",
    name: "Web App Triage (Safe scripts set)",
    category: "web",
    tags: ["web", "scripts", "triage"],
    cmd: ["-p 80,443", "--script", "http-enum,http-security-headers,http-robots.txt", "--reason"],
    details: "Enumeration + security headers + robots.txt (training-friendly).",
    mapping: "MITRE: T1595 (Active Scanning) • CIS: Secure Configuration",
    sample: `PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /admin/: Potentially interesting folder
|_  /backup/: Potentially interesting folder
| http-robots.txt:
|_  Disallow: /staging/
| http-security-headers:
|   X-Frame-Options: SAMEORIGIN
|_  Content-Security-Policy: missing`,
    meaning: "Interesting directories and a staging path were discovered. Security headers are incomplete.",
    risk: "🟠 Medium — exposed admin/staging paths can lead to compromise if not protected.",
    next: "Verify access controls on /admin and /staging, remove backups from web root, add missing headers."
  },

  // ---------- WINDOWS ----------
  {
    id: "windows_smb_check",
    name: "Windows SMB Triage (445)",
    category: "windows",
    tags: ["windows", "smb", "445"],
    cmd: ["-p 445", "-sV", "--script", "smb2-security-mode,smb2-time,smb-os-discovery", "--reason"],
    details: "Quick SMB checks: OS discovery + security mode (training-friendly).",
    mapping: "MITRE: T1135 (Network Share Discovery) • CIS: Secure Configuration for SMB",
    sample: `Nmap scan report for 10.0.0.50
Host is up (0.008s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows Server 2019 Standard 17763
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763
|_  Computer name: FILESRV01

Nmap done: 1 IP address (1 host up) scanned in 9.61 seconds`,
    meaning: "SMB is exposed. Signing is enabled but not required — this may be a security gap.",
    risk: "🟠 Medium/High — SMB misconfigurations are often abused in lateral movement.",
    next: "Require SMB signing, limit SMB exposure, check for abnormal share access, validate domain policies."
  },
  {
    id: "windows_rdp_cert",
    name: "Windows RDP Certificate Check (3389)",
    category: "windows",
    tags: ["rdp", "3389", "cert"],
    cmd: ["-p 3389", "--script", "rdp-enum-encryption,ssl-cert", "--reason"],
    details: "Checks RDP encryption and shows server certificate info.",
    mapping: "MITRE: T1021 • CIS: Secure Configuration",
    sample: `PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|_  RDP Encryption level: High
| ssl-cert:
|   Subject: commonName=WIN-SERVER
|   Issuer: commonName=WIN-SERVER
|_  Self-signed certificate`,
    meaning: "RDP uses high encryption, but certificate is self-signed (common internally).",
    risk: "🟡 Medium — ensure RDP is not internet-exposed and is restricted by VPN/ACL.",
    next: "Limit exposure, enforce MFA, monitor failed logins, consider managed certificates for enterprise environments."
  },
  {
    id: "windows_ad_ports_baseline",
    name: "AD/Domain Controller Ports Baseline",
    category: "windows",
    tags: ["ad", "kerberos", "ldap", "dns"],
    cmd: ["-sS", "-p 53,88,135,139,389,445,464,636,3268,3269", "-sV", "--reason"],
    details: "Baseline scan for common AD/DC ports (inventory + quick validation).",
    mapping: "MITRE: T1018 • CIS: Asset Inventory",
    sample: `Nmap scan report for DC01.domain.local
Host is up (0.010s latency).
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
389/tcp  open  ldap
445/tcp  open  microsoft-ds
636/tcp  open  ldaps
3268/tcp open  globalcatLDAP`,
    meaning: "Ports match a typical Domain Controller profile.",
    risk: "🟠 Medium — DC exposure should be tightly controlled.",
    next: "Verify DC is only reachable from approved subnets; monitor for abnormal LDAP/Kerberos activity."
  },

  // ---------- LINUX ----------
  {
    id: "linux_ssh_hardening",
    name: "Linux SSH Hardening Check (22)",
    category: "linux",
    tags: ["linux", "ssh", "22"],
    cmd: ["-p 22", "-sV", "--script", "ssh2-enum-algos,ssh-hostkey", "--reason"],
    details: "See SSH algorithms and host keys (hardening & auditing).",
    mapping: "MITRE: T1021 (Remote Services) • CIS: Secure Configuration",
    sample: `Nmap scan report for 192.168.1.10
Host is up (0.010s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
| ssh2-enum-algos:
|   kex_algorithms: curve25519-sha256, diffie-hellman-group14-sha256
|   server_host_key_algorithms: ssh-ed25519, rsa-sha2-512
|_  encryption_algorithms: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com

Nmap done: 1 IP address (1 host up) scanned in 6.18 seconds`,
    meaning: "SSH supports modern algorithms (good sign). Confirm password login and MFA policy separately.",
    risk: "🟢/🟡 Low–Medium — depends on whether SSH is internet-facing and how it’s authenticated.",
    next: "Enforce key-based auth, disable password auth if possible, review allowed users/groups, monitor login failures."
  },
  {
    id: "linux_rpc_nfs_quick",
    name: "Linux NFS/RPC Quick Check",
    category: "linux",
    tags: ["nfs", "rpc", "2049"],
    cmd: ["-p 111,2049", "-sV", "--script", "nfs-showmount,rpcinfo", "--reason"],
    details: "Detects NFS exports and RPC services (common misconfig vector).",
    mapping: "MITRE: T1135 • CIS: Secure Configuration",
    sample: `PORT     STATE SERVICE
111/tcp  open  rpcbind
2049/tcp open  nfs
| nfs-showmount:
|_  /exports (everyone)
| rpcinfo:
|   program version port/proto service
|_  100003  3,4   2049/tcp nfs`,
    meaning: "NFS exports appear accessible to everyone — often a misconfiguration.",
    risk: "🔴 High — exposed NFS can leak sensitive data.",
    next: "Restrict exports, enforce subnet ACLs, review file permissions, and audit access logs."
  },

  // ---------- DNS ----------
  {
    id: "dns_version_check",
    name: "DNS Service Check (53)",
    category: "dns",
    tags: ["dns", "53", "infra"],
    cmd: ["-p 53", "-sV", "--reason"],
    details: "Basic DNS service validation (inventory).",
    mapping: "CIS: Secure Configuration • SOC: Infra Validation",
    sample: `PORT   STATE SERVICE VERSION
53/tcp open  domain  ISC BIND 9.16.1`,
    meaning: "DNS server identified (BIND).",
    risk: "🟡 Medium — DNS is critical infrastructure.",
    next: "Confirm patch level, restrict recursion, monitor for unusual query spikes."
  },
  {
    id: "dns_zone_transfer_test",
    name: "DNS Zone Transfer Test (AXFR) – Training",
    category: "dns",
    tags: ["dns", "axfr", "misconfig"],
    cmd: ["-p 53", "--script", "dns-zone-transfer", "--reason"],
    details: "Checks if a DNS zone transfer is allowed (common misconfiguration check).",
    mapping: "MITRE: T1590 (Gather Victim Network Information) • CIS: Secure Configuration",
    sample: `PORT   STATE SERVICE
53/tcp open  domain
| dns-zone-transfer:
|_  Transfer failed (denied)`,
    meaning: "Zone transfer is denied (good).",
    risk: "🟢 Low — expected secure behavior.",
    next: "If transfer succeeds in your lab, fix by restricting AXFR to authorized secondary DNS servers."
  },

  // ---------- MAIL ----------
  {
    id: "mail_smtp_banner",
    name: "SMTP Banner + Capabilities (25/587)",
    category: "mail",
    tags: ["smtp", "mail", "25", "587"],
    cmd: ["-p 25,587", "-sV", "--script", "smtp-commands", "--reason"],
    details: "Mail server quick triage: commands and banner (inventory).",
    mapping: "CIS: Secure Configuration • SOC: Email Infrastructure",
    sample: `PORT    STATE SERVICE
25/tcp  open  smtp
| smtp-commands:
|_  PIPELINING SIZE 10240000 STARTTLS AUTH HELP
587/tcp open  submission
| smtp-commands:
|_  STARTTLS AUTH HELP`,
    meaning: "SMTP supports STARTTLS and AUTH — typical for mail infrastructure.",
    risk: "🟡 Medium — ensure strong TLS and auth policies.",
    next: "Verify TLS settings, check for open relay configuration, monitor for spam bursts."
  },
  {
    id: "mail_imap_pop",
    name: "IMAP/POP Exposure Check (143/993/110/995)",
    category: "mail",
    tags: ["imap", "pop3", "mail"],
    cmd: ["-p 110,143,993,995", "-sV", "--reason"],
    details: "Checks mail client access ports (inventory/exposure).",
    mapping: "CIS: Secure Configuration",
    sample: `PORT    STATE SERVICE  VERSION
143/tcp open  imap     Dovecot imapd
993/tcp open  imaps?
110/tcp closed pop3
995/tcp closed pop3s`,
    meaning: "IMAP is enabled; POP3 is closed (good if not needed).",
    risk: "🟡 Medium — confirm IMAP access is restricted and secured with TLS.",
    next: "Disable legacy ports if possible, enforce modern auth/MFA, monitor failed logins."
  },

  // ---------- DATABASE ----------
  {
    id: "db_mysql_postgres_mssql",
    name: "Database Ports Exposure (MySQL/Postgres/MSSQL)",
    category: "database",
    tags: ["db", "mysql", "postgres", "mssql"],
    cmd: ["-sS", "-p 1433,3306,5432", "-sV", "--reason"],
    details: "Quick exposure check for common database ports.",
    mapping: "CIS: Network Segmentation • SOC: Data Protection",
    sample: `Nmap scan report for 10.0.0.60
Host is up (0.011s latency).
PORT     STATE SERVICE  VERSION
3306/tcp open  mysql    MySQL 8.0.34
5432/tcp closed postgresql
1433/tcp filtered ms-sql-s`,
    meaning: "MySQL is reachable; others are closed/filtered. Confirm this is expected and segmented.",
    risk: "🟠 Medium — databases should rarely be reachable from broad networks.",
    next: "Restrict to app subnets, confirm auth settings, check for recent config changes, monitor DB logs."
  },
  {
    id: "db_redis_exposure",
    name: "Redis Exposure Check (6379)",
    category: "database",
    tags: ["redis", "6379", "exposure"],
    cmd: ["-p 6379", "-sV", "--reason"],
    details: "Checks if Redis is exposed (often should be internal only).",
    mapping: "CIS: Network Segmentation",
    sample: `PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 6.2.6`,
    meaning: "Redis service is reachable. If internet-facing, this is a serious risk.",
    risk: "🔴 High — Redis exposure has led to widespread compromise historically.",
    next: "Restrict to localhost/VPC, enforce auth, disable dangerous commands, and rotate secrets."
  },

  // ---------- INCIDENT RESPONSE ----------
  {
    id: "incident_ir_quick",
    name: "Incident Response Quick Scan (Snapshot)",
    category: "incident",
    tags: ["incident", "ir", "triage"],
    cmd: ["-sS", "--top-ports 50", "-sV", "--reason"],
    details: "Fast triage snapshot of common ports during an incident (controlled).",
    mapping: "MITRE: T1046 • IR: Rapid Service Validation",
    sample: `Nmap scan report for 10.0.0.77
Host is up (0.007s latency).
PORT     STATE SERVICE   VERSION
53/tcp   open  domain    (unknown)
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Nmap done: 1 IP address (1 host up) scanned in 11.02 seconds`,
    meaning: "Host exposes Windows management-related services. Confirm if expected for that asset.",
    risk: "🟠 Medium — admin services can be abused for lateral movement if compromised.",
    next: "Check EDR for suspicious processes, review auth logs, verify recent changes, isolate if indicators present."
  },
  {
    id: "incident_suspicious_listener",
    name: "Incident: Suspicious Listener Check (Common backdoor ports)",
    category: "incident",
    tags: ["incident", "suspicious", "backdoor"],
    cmd: ["-sS", "-p 4444,5555,6666,31337,12345", "-sV", "--reason"],
    details: "Checks a small set of commonly abused ports (use only in approved IR playbooks).",
    mapping: "MITRE: T1059/T1046 (Contextual) • IR: Validation",
    sample: `Nmap scan report for 10.0.0.91
Host is up (0.008s latency).
PORT     STATE SERVICE VERSION
4444/tcp open  unknown
31337/tcp closed Elite

Nmap done: 1 IP address (1 host up) scanned in 1.91 seconds`,
    meaning: "Port 4444 is open and unidentified — treat as suspicious until verified by host telemetry.",
    risk: "🔴 High — unknown service on a commonly abused port.",
    next: "Correlate with EDR/netflow, identify process bound to port, capture memory if needed, isolate if confirmed malicious."
  },

  // ---------- AUDIT / CHANGE ----------
  {
    id: "audit_change_detection_workflow",
    name: "Change Detection (Save baseline file)",
    category: "audit",
    tags: ["audit", "change", "baseline"],
    cmd: ["-sS", "--top-ports 100", "-sV", "--reason", "-oN baseline.txt"],
    details: "Generate a baseline file; run later and compare after changes (workflow template).",
    mapping: "CIS: Continuous Monitoring • SOC: Drift Detection",
    sample: `# Baseline saved: baseline.txt
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1
80/tcp  open  http     nginx 1.18.0

# Later run shows:
# + 3306/tcp open mysql  MySQL 8.0.34  (NEW)`,
    meaning: "Baseline helps detect drift. New ports/services should trigger review/approval checks.",
    risk: "🟡 Medium — change without ticket/approval can be misconfig or compromise.",
    next: "Validate change ticket, confirm owner, ensure firewall rules are correct, and run vuln checks on new service."
  }
];

// ====== DOM ======
const el = (id) => document.getElementById(id);

const state = {
  selected: null
};

// ====== Helpers ======
function escapeForShell(target){
  // Basic safety: prevent accidental shell injection in copy/paste commands
  // Allow: letters, digits, dots, dashes, slashes, colons, underscores, CIDR
  const safe = target.trim();
  if (!safe) return "";
  const ok = /^[a-zA-Z0-9.\-_:\/]+$/.test(safe);
  return ok ? safe : "";
}

function getSettingsFlags(){
  const flags = [];
  if (el("noDNS").checked) flags.push("-n");
  if (el("treatUp").checked) flags.push("-Pn");
  if (el("t2").checked) flags.push("-T2");
  if (el("maxRate").checked) flags.push("--max-rate 100");
  if (el("maxRetries").checked) flags.push("--max-retries 2");
  if (el("hostTimeout").checked) flags.push("--host-timeout 2m");
  return flags;
}

function buildCommand(scan){
  const targetRaw = el("target").value;
  const target = escapeForShell(targetRaw);

  if (!target) {
    return "Enter a valid target (letters/numbers/dot/dash/CIDR) to generate a safe command…";
  }

  const parts = [];
  if (el("useSudo").checked) parts.push("sudo");
  parts.push("nmap");

  parts.push(...scan.cmd);
  parts.push(...getSettingsFlags());
  parts.push(target);

  return parts.join(" ");
}

function renderSelected(scan){
  state.selected = scan;

  el("selectedScan").textContent = `${scan.name}  •  ${scan.category.toUpperCase()}`;
  el("scanDetails").textContent = scan.details;
  el("mapping").textContent = scan.mapping;

  el("cmd").textContent = buildCommand(scan);

  el("out").textContent = scan.sample;
  el("meaning").textContent = scan.meaning;
  el("risk").textContent = scan.risk;
  el("next").textContent = scan.next;
}

function renderList(){
  const q = el("search").value.trim().toLowerCase();
  const cat = el("category").value;

  const items = SCANS.filter(s => {
    const inCat = (cat === "all") || (s.category === cat);
    const text = (s.name + " " + s.tags.join(" ")).toLowerCase();
    const inSearch = !q || text.includes(q);
    return inCat && inSearch;
  });

  el("scanList").innerHTML = items.map(s => `
    <div class="scan" data-id="${s.id}">
      <div class="title">${s.name}</div>
      <div class="meta">
        <span><b>Category:</b> ${s.category}</span><br/>
        <span><b>Tags:</b> ${s.tags.join(", ")}</span>
      </div>
    </div>
  `).join("");

  document.querySelectorAll(".scan").forEach(card => {
    card.addEventListener("click", () => {
      const scan = SCANS.find(x => x.id === card.dataset.id);
      if (scan) renderSelected(scan);
    });
  });
}

async function copyText(text){
  try{
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

// ====== History (localStorage) ======
const HIST_KEY = "nmap_blue_team_history_v1";

function loadHistory(){
  try { return JSON.parse(localStorage.getItem(HIST_KEY) || "[]"); }
  catch { return []; }
}
function saveHistory(list){
  localStorage.setItem(HIST_KEY, JSON.stringify(list));
}

function simpleDiff(aLines, bLines){
  const aSet = new Set(aLines);
  const bSet = new Set(bLines);

  const removed = aLines.filter(l => l.trim() && !bSet.has(l)).slice(0, 25);
  const added   = bLines.filter(l => l.trim() && !aSet.has(l)).slice(0, 25);

  let out = "";
  removed.forEach(l => out += `- ${l}\n`);
  added.forEach(l => out += `+ ${l}\n`);
  return out.trim();
}

function renderHistory(){
  const list = loadHistory();
  if (!list.length){
    el("history").textContent = "No saved outputs yet.";
    el("diff").textContent = "—";
    return;
  }

  el("history").innerHTML = list.slice().reverse().map(item => `
    <div style="border-bottom:1px solid #223044; padding:10px 0;">
      <div><b>${item.scanName}</b> <span class="muted">• ${new Date(item.ts).toLocaleString()}</span></div>
      <div class="muted" style="margin-top:6px;"><b>Target:</b> ${item.target || "(not set)"} </div>
      <div class="muted"><b>Command:</b> <code>${item.command}</code></div>
    </div>
  `).join("");

  if (list.length >= 2){
    const a = list[list.length - 2].output.split("\n");
    const b = list[list.length - 1].output.split("\n");
    const changes = simpleDiff(a, b);
    el("diff").textContent = changes || "(No obvious line changes detected)";
  } else {
    el("diff").textContent = "Save one more output to compare.";
  }
}

function maybeSaveOutput(){
  if (!el("saveOutputs").checked) return;
  const scan = state.selected;
  if (!scan) return;

  const target = escapeForShell(el("target").value);
  const entry = {
    ts: Date.now(),
    scanId: scan.id,
    scanName: scan.name,
    target: target || "",
    command: el("cmd").textContent,
    output: el("out").textContent
  };

  const list = loadHistory();
  list.push(entry);
  saveHistory(list);
  renderHistory();
}

// ====== Events ======
function bind(){
  // modal
  el("openLegal").addEventListener("click", () => el("modal").classList.remove("hidden"));
  el("closeLegal").addEventListener("click", () => el("modal").classList.add("hidden"));
  el("modal").addEventListener("click", (e) => {
    if (e.target.id === "modal") el("modal").classList.add("hidden");
  });

  // quick guide
  el("quickGuide").addEventListener("click", (e) => {
    e.preventDefault();
    alert("Quick Guide:\\n1) Enter a target\\n2) Pick a scan\\n3) Copy command\\n4) Run only with permission\\n5) Use sample outputs + SOC notes for training");
  });

  // example target
  el("exampleTarget").addEventListener("click", () => {
    el("target").value = "192.168.1.10";
    if (state.selected) el("cmd").textContent = buildCommand(state.selected);
  });

  // search/filter
  el("search").addEventListener("input", renderList);
  el("category").addEventListener("change", renderList);

  // settings -> update command live
  ["target","useSudo","noDNS","treatUp","t2","maxRate","maxRetries","hostTimeout"].forEach(id => {
    el(id).addEventListener("input", () => {
      if (state.selected) el("cmd").textContent = buildCommand(state.selected);
    });
    el(id).addEventListener("change", () => {
      if (state.selected) el("cmd").textContent = buildCommand(state.selected);
    });
  });

  // copy buttons
  el("copyCmd").addEventListener("click", async () => {
    await copyText(el("cmd").textContent);
  });

  el("copyOut").addEventListener("click", async () => {
    await copyText(el("out").textContent);
    maybeSaveOutput();
  });

  // reset
  el("reset").addEventListener("click", () => {
    el("target").value = "";
    state.selected = null;
    el("selectedScan").textContent = "No scan selected";
    el("cmd").textContent = "Select a scan to generate a command…";
    el("scanDetails").textContent = "Select a scan to see details…";
    el("mapping").textContent = "Select a scan to see mapping…";
    el("out").textContent = "Select a scan to view a sample output…";
    el("meaning").textContent = "—";
    el("risk").textContent = "—";
    el("next").textContent = "—";
  });

  // history clear
  el("clearHistory").addEventListener("click", () => {
    localStorage.removeItem(HIST_KEY);
    renderHistory();
  });
}

// ====== Init ======
renderList();
bind();
renderHistory();
