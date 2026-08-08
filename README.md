# Security Research Notes

🔗 **Live site:** https://housekeeping101.github.io/sec-research-site/

Published cybersecurity research: attack technique writeups (with MITRE ATT&CK mapping and detection queries), malware/TTP research extractions, threat actor profiles, DFIR/forensics reference notes, threat hunting playbooks, and tooling notes.

## How this is published

This site is generated from a private Obsidian research vault. Notes are only published here once they're explicitly cleared for git tracking in that vault (a whitelist-gated `.gitignore`, not a blocklist) — nothing leaves the vault by default. A GitHub Action in the vault repo syncs cleared notes over on every relevant push, and this repo's own Action rebuilds and redeploys the site via [Quartz](https://quartz.jzhao.xyz/), a static site generator built for publishing Obsidian-style notes.

## Structure

- `content/` — the published notes (source of truth lives in the private vault)
- `quartz.config.yaml` — site configuration
- everything else is the Quartz v5 site generator itself
