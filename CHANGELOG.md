# Changelog

What changed in each release of fwscope. The newest is at the top. Version numbers follow [semantic versioning](https://semver.org/).

## Unreleased

### Changed
- **A tidier dashboard** (about a third shorter on the sample):
  - a **jump bar** that stays at the top, with a link to each part of the dashboard that's showing
  - **fold any card** by its heading or arrow; folded cards stay folded next time
  - the events table shows **25 rows** by default, with a picker for 100 or 500
  - **block suggestions** list the strongest 15 first, with **Show all** (and how many of the hidden ones are ticked)
  - cards with nothing to show (no tuning candidates, no scans, nothing to compare) shrink to their heading
- fwscope-pull's helper page: fields sit under their labels, and its controls follow the dark theme.

## 1.4.0 (2026-11-08)

### Added
- **fwscope-pull.py:** a Python script (no dependencies; Windows, macOS, Linux) that gathers logs onto the computer you run fwscope on: this machine, Linux servers, OPNsense / pfSense and OpenWrt over SSH, Cloudflare events past the 10,000-per-request limit, and AWS / Azure flow logs through their command-line tools. Each format's tab on the start screen shows its command.
- **fwscope-pull.py gui:** a page in your browser to run pulls and open the results straight in fwscope, without the command line or dragging a folder. It listens on this computer only and needs a random key.

### Changed
- Host names come from file names like `web1-modsec_audit.log` (as the script names them): the host is `web1`. fail2ban logs now take their host from the file name too.

## 1.3.0 (2026-11-08)

### Added
- **OpenWrt:** firewall logs from `logread` or a syslog server, fw4 (`drop wan in:`) and fw3 (`DROP(src wan)`). The verdict is the action and the zone the rule.
- **AWS VPC Flow Logs:** default and custom formats from S3, and CloudWatch exports.
- **Azure flow logs:** NSG flow logs and VNet flow logs (`PT1H.json`), each flow counted once.
- **Reopen your last session:** the parsed events of your last load are kept in this browser and reopen in a moment, without reading the files again. Turn it off with **Remember last load**.
- **fail2ban repeats:** `already banned` warnings show as **F2B REPEAT**: an address that came back while banned, a sign the ban action isn't stopping it.
- **Since your last visit:** a card listing new sources, newly targeted ports, attack types, rules and countries since earlier visits, and the events newer than what you last saw.

### Changed
- **A shorter start screen:** the drop zone is down to a few lines, with a **Try it on sample data** button. The setup help shows one log format at a time (and remembers which), with turning logging on and grabbing the log in one place. GeoIP, rule names and blocklists fold away under **Optional extras**. **Folder** and **Paste** moved into a menu on **Open logs**.

## 1.2.0 (2026-11-08)

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
