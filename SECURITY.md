# Security

fwscope runs entirely in your browser. Logs, GeoIP databases and firewall configs are read locally and never uploaded. The page makes no network requests of its own; the only outside links (AbuseIPDB, RDAP) open when you click them.

## Reporting a problem

If you find a security issue, for example a crafted log line that runs script in the page, or anything that sends data somewhere it shouldn't, please report it privately:

- **GitHub:** [Report a vulnerability](https://github.com/magikh0e/fwscope/security/advisories/new) (private to the maintainer)

Please don't open a public issue for it. I'll reply as soon as I can and credit you in the fix unless you'd rather I didn't.

## Supported versions

Only the latest version on `main` gets fixes.
