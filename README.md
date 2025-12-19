# Nmap Blue Team Toolkit (GitHub Pages)

Interactive **command builder** + **sample outputs** + **SOC triage guidance** for Nmap.  
✅ Intended for **authorized security testing** and **blue-team education**.  
🚫 This website does **not** perform scanning.

## Features
- Scan Library (Discovery, Enumeration, UDP, Web, Windows/SMB, Reporting)
- Command Builder (target + safe options like timing/rate/output files)
- Sample outputs to teach interpretation
- “What it means” + “Next steps” per scan
- Clean UI (no frameworks) — works great on GitHub Pages

## Quick start (local)
1. Download the repo
2. Open `index.html` in a browser  
   (or run a local server for module imports):
   ```bash
   python3 -m http.server 8080
   ```
3. Visit `http://localhost:8080`

## Deploy on GitHub Pages
1. Create a GitHub repo (public recommended)
2. Upload all files from this package
3. Go to **Settings → Pages**
4. Source: **Deploy from a branch**
5. Branch: `main` / folder: `/ (root)`
6. Save — your site will appear at GitHub Pages URL

## Customize
- Change footer “Your Name” in `index.html`
- Add/remove scans in `assets/scans.json`
- Update style in `assets/styles.css`

## Legal
Use only on systems you own or have explicit permission to test.
