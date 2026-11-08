<p align="center"><img src="assets/fwscope-badge.webp" alt="fwscope: firewall log visualizer" width="320"></p>

# fwscope

A single-file, offline visualizer for UFW / iptables, OPNsense / pfSense and Windows Firewall logs. Open `index.html` in a browser, drop your logs on it, and you get a dashboard. Everything is parsed in the browser tab. Nothing gets uploaded, and there are no dependencies or CDN calls, so it also works on an air-gapped box.

## What it reads

- `/var/log/ufw.log`, `kern.log`, `syslog`, including rotated `.gz` files (gzip is detected by magic bytes)
- `journalctl` text output (`short`, `short-iso`) and `journalctl -o json`
- `dmesg -T` (plain `dmesg` works too, but those lines have no wall-clock time, so they're left out of the time charts)
- Pasted lines

Lines without a `[UFW ...]` tag are ignored, so you can feed it a whole `syslog`. Drop several files at once to merge them. UFW's default rsyslog config writes each line to `ufw.log`, `kern.log` *and* `syslog`, so a line that shows up again in a later file is skipped as a duplicate.

### Getting the logs

```bash
sudo cp /var/log/ufw.log* ~/ && sudo chown $USER ~/ufw.log*
journalctl -k -g 'UFW ' -o short-iso --since '-7d' > ufw-journal.log
journalctl -k -g 'UFW ' -o json > ufw.json
```

`sudo ufw logging medium` also logs allowed new connections (ALLOW). At `low`, you only see blocks and rate-limited hits.

## OPNsense / pfSense

It also reads `filterlog` lines, in any of these forms:

- OPNsense's local files, `/var/log/filter/filter_YYYYMMDD.log` (RFC 5424, `<134>1 2026-11-07T... host filterlog ...`)
- BSD syslog, as sent to a remote syslog server (`Nov  7 18:23:45 fw filterlog[123]: ...`)
- JSON from the API behind Firewall → Log Files → Live View (`/api/diagnostics/firewall/log`), either as an array or one object per line. This form includes the interface names (WAN, LAN) and rule descriptions.

Getting the files:

```bash
scp 'root@opnsense:/var/log/filter/filter_*.log' .
ssh root@opnsense 'cat /var/log/filter/filter_*.log' > opnsense-filter.log
```

How OPNsense data maps onto the dashboard:

- `pass` shows as PASS, under the ALLOW/PASS group. `block` and `reject` count as blocks.
- The logged interface becomes **In** or **Out**, depending on the packet's direction.
- The syslog hostname becomes **Host**, so you can merge a router and a server in one view.
- The matching rule becomes a **Rule** column, a "Firewall rules" Top list, and a `rule:` filter. A plain log only has the rule's 32-character ID, which the page shortens. To see which rule an ID belongs to, look it up in OPNsense under Firewall → Rules.

Plain `filterlog` lines don't contain interface descriptions, so you'll see `igb0` / `vtnet1` rather than WAN / LAN.

## Windows Firewall

It reads `pfirewall.log`, the Windows Firewall log, including the rotated `pfirewall.log.old`. Logging is off by default. In an admin PowerShell, turn it on and copy the log out (the file is only readable as admin):

```powershell
Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 32767
Copy-Item C:\Windows\System32\LogFiles\Firewall\pfirewall.log* $HOME\Desktop\
```

Add `-LogAllowed True` to log allowed connections too; that's very noisy on a desktop. 32767 KB is the largest log Windows allows, and it keeps one older copy.

How it maps onto the dashboard:

- `DROP` counts as a block and `ALLOW` as allowed.
- The log has no interface names, so **In** shows `receive` for inbound packets and **Out** shows `send` for outbound ones. Filter with `in:receive` or `out:send`.
- The log has no hostname either. **Host** is the file name, so rename each copy after its PC (`office-pc.log`) to tell machines apart. Otherwise it shows as `windows`. A `#Host: name` line at the top of the file also works.
- No rule name or TTL is logged. Times are local with no timezone, so they're read as your browser's local time.
- The parser follows the `#Fields:` header, so the extra process-ID column on newer Windows builds is fine.

## What you get

- **Stat tiles**: events by action, unique sources, destination ports, busiest source, time span
- **Events over time**: stacked by action (BLOCK / LIMIT / ALLOW / AUDIT). Drag to zoom into a range, double-click to reset.
- **Two "Top" lists**, each switchable: sources, source subnets (/24 and /64), destinations, destination and source ports (with service names), protocols, in/out interfaces, ICMP types, source MACs, logging hosts, exact action tags
- **Weekday × hour heatmap**
- **Likely port scans**: sources ranked by how many distinct destination ports they hit
- **Event table** with paging. Click any cell to filter on it.
- **Exports**: CSV of the current filter, a source IP list, and `ufw deny` rules for the top public sources (review those before you run them)

Click any row or cell to filter on it. Shift-click excludes it instead.

## World map and network owners (GeoIP)

Drop a GeoIP database in `.mmdb` format on the page (or use **Add GeoIP database** on the map card). `.mmdb.gz` works as downloaded. You get:

- a world map shaded by events per source country (log scale; small countries like Singapore and Hong Kong show as dots)
- a "Top" list next to it for source networks (ASN) or countries, plus both as options in the other Top lists
- country and network columns in the event table, the port-scan table and the CSV export
- `cc:` and `asn:` / `org:` filters (see below)

Free databases:

- **[DB-IP Lite](https://db-ip.com/db/lite.php)**: "IP to Country Lite" + "IP to ASN Lite", MMDB format. No account, CC BY 4.0, updated monthly. The page shows the attribution DB-IP asks for.
- **[IPinfo Lite](https://ipinfo.io/lite)**: country and ASN in one file, free with a sign-up.
- **[MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)** Country / ASN: free account and license key.

Load a country file and an ASN file together and they're combined. DB-IP's ASN file has no countries, so with only that file the map stays empty. The page says so when that happens. The databases are kept in the browser's IndexedDB, so you only add them once. Loading a newer copy of the same database replaces the old one, and **Forget databases** clears them. Lookups happen in the page; no IP leaves your machine.

Country-level accuracy is good, but scanners mostly live on cloud and hosting networks, so the ASN ("DigitalOcean", "Censys") usually tells you more than the flag. Private, link-local and multicast sources have no location and are left off the map.

The sample data uses documentation IPs that have no real location, so it gets made-up countries and the documentation ASNs (AS64496–64511) to show what the map looks like.

The map outline is Natural Earth 1:110m (public domain), projected (Equal Earth) and embedded by `tools/build-map.mjs`. Rerun that with Node 18+ to regenerate it.

The header emblem and favicon are drawn from that same map by `tools/build-logo.mjs`, which also writes `assets/logo.svg` and `assets/favicon.svg`. Run it after `build-map.mjs`. `assets/fwscope-badge.webp` is the full badge with lettering.

## Filter syntax

The filter box takes space-separated terms. All of them must match.

| Term | Example |
|---|---|
| `src:` `dst:` `ip:` (either) | `src:203.0.113.7`, `src:203.0.113.0/24`, `dst:2001:db8::/32`, `ip:192.168.1.*` |
| `spt:` `dpt:` `port:` (either) | `dpt:22`, `dpt:22,23,3389`, `dpt:1-1024` |
| `proto:` | `proto:tcp`, `proto:icmpv6` |
| `in:` `out:` `iface:` | `in:eth0`, `iface:wg*` |
| `rule:` | `rule:fae55933` (prefix of an OPNsense rule ID), `rule:#96`, `rule:Default_deny*` |
| `host:` | `host:web1` (the machine that wrote the log, for merged files) |
| `act:` | `act:block`, `act:limit_block`, `act:audit_invalid` |
| `flag:` | `flag:syn`, `flag:rst` (SYN ACK FIN RST PSH URG ECE CWR DF) |
| `type:` `ttl:` `len:` | `type:8` (ICMP echo request), `ttl:1-10` |
| `cc:` `country:` | `cc:CN`, `-cc:US` (needs a country database) |
| `asn:` `org:` | `asn:14061`, `asn:AS14061`, `org:digitalocean`, `org:*cloud*` (needs an ASN database) |
| `-term` | exclude: `-proto:udp`, `-src:192.168.0.0/16` |
| bare | an IP/CIDR matches either end, a number matches either port, and other text is matched against protocol, interface, host, action and IP |

The filter bar also has time presets (relative to the newest event in the logs, not the clock), action toggles, **Hide broadcast/multicast** (drops mDNS, SSDP, NetBIOS and IGMP LAN chatter, which is most of a home box's UFW log), and **Public sources only**.

## Notes

- Classic syslog timestamps have no year or timezone. The year is inferred from the file's modified date, and the time is read as your browser's local time. ISO and journal timestamps carry their offset and are converted to your local time.
- Tested to about 550K events (137 MB) in a few seconds. Data is stored in columns of typed arrays, so filtering stays fast.
- **Sample data** generates a fake week of logs using the documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), so no real addresses are implicated.

## License

Copyright (C) 2026 magikh0e

fwscope is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; see [LICENSE](LICENSE) for the full text.

Bundled data keeps its own terms: the country outlines are Natural Earth (public domain) and the country names come from [i18n-iso-countries](https://github.com/michaelwittig/node-i18n-iso-countries) (MIT). GeoIP databases are not included; each one is under its provider's license.
