# Changelog

What changed in each release of fwscope. The newest is at the top. Version numbers follow [semantic versioning](https://semver.org/).

## Unreleased

### Added
- **Suricata alerts:** `eve.json` (alert events, also when forwarded through syslog) and `fast.log`. Signatures show as rules, IPS drops as blocks, and `seen:ids` filters to sources Suricata alerted on.
- **Blocklists:** drop a list of addresses and ranges (Spamhaus DROP, FireHOL, your own) to mark sources on it, filter them with `listed:`, and weigh it in block suggestions. Checked offline, and kept in the browser until removed.
- **Loaded files card:** each file's events, duplicates and skipped lines, with a **Remove** button that re-reads the others.
- **Folders:** drop a folder (subfolders included) or pick one with **Folder**.
- The sample data includes Suricata alerts.

### Changed
- Files are parsed in a background worker, so the page stays responsive during big loads and **Stop** reacts at once. If a browser won't start the worker, parsing runs on the page as before.

## 1.1.0 (2026-11-08)

### Added
- **Add files to what's loaded:** once logs are open, the button reads **Add logs**. Opening or dropping more files adds them to the dashboard, and a note says how many new events each added and how many duplicates were skipped. Your filter, view and block ticks stay as they were. **Clear** starts over.
- **fail2ban caught or missed:** with a fail2ban log loaded, the Scans card marks each scanner or hammerer as *fail2ban banned* or *not banned*. Block suggestions say the same. The Sources list notes *banned by fail2ban*, and `seen:f2b` filters to the sources it banned.
- The sample data now includes an nftables host, a fail2ban log and Cloudflare firewall events.
- Saved HTML reports carry the fwscope version and credit line.
- A credit line on every screen: author, source, license and support links.

### Changed
- The rate-limit filter chip reads **CHALLENGE** or **LIMIT/CHALLENGE** when Cloudflare challenges are loaded.
- fail2ban lines no longer count as "seen by the firewall" in the firewall + WAF cross-check.

### Fixed
- Pasting log lines while the sample was showing mixed them into the sample. They now replace it, as opened files do.
- The footer no longer says Cloudflare's own firewall events were unwrapped from `CF-Connecting-IP`. It counts them separately.

## 1.0.0 (2026-11-07)

The first release.

- **Firewalls:** UFW; nftables, iptables and firewalld log lines (any log prefix); OPNsense / pfSense filterlog; Windows Firewall (`pfirewall.log`, or the Security log for program names); fail2ban's log.
- **WAFs:** ModSecurity and Coraza (v3 JSON, mod_security2 JSON, native audit log, Apache and nginx error-log lines); Cloudflare firewall events (GraphQL API or Logpush).
- **Dashboard:** events over time, top lists, heatmap, sortable events table, filter language with click-to-filter, saved views, GeoIP map and network owners, scan and hammering detection, new-in-the-last and compare cards.
- **WAF analysis:** attack types, anomaly scores, real visitors behind Cloudflare or a proxy, fake-crawler checks, "if blocking were on" thresholds, and tuning suggestions with drafted exclusions.
- **Acting on it:** block suggestions with scripts and undo scripts (UFW, ipset, nftables, OPNsense, Windows, ModSecurity, Cloudflare), fail2ban drafts, abuse reports, saved HTML reports.
- Optional reverse DNS over DNS-over-HTTPS, off by default.
- A test suite (Node's test runner and jsdom) that runs on every push.
