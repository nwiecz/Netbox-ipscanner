# NetBox IP Scanner

ICMP scan script for populating the IPAM module in NetBox.

Reads all IPv4 prefixes, performs an ICMP ping scan, and syncs results into the IPAM module — creating missing entries, updating DNS names, and deprecating unresponsive addresses.

[![NetBox](https://img.shields.io/badge/NetBox-4.6%2B-blue)](https://github.com/netbox-community/netbox)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## ✨ Features

- ICMP scan all prefixes (or filter by tag)
- Automatically creates unknown responding IPs in NetBox
- Updates DNS names if changed
- Marks non-responding existing IPs as **Deprecated**
- Dry-run mode (`commit=False`) for safe testing
- Batch queries & atomic transactions for performance & consistency
- Skips **Reserved** and **Container** prefixes
- IPv6 prefixes are safely skipped with a warning (no crash)

---

## Compatibility

| NetBox Version | Status | Notes |
|----------------|--------|-------|
| **4.6.x** | ✅ Active | Tested against 4.6.4 — native Django ORM, no REST API |
| **3.7** | ❌ Legacy | Last working version: [v1.3](https://github.com/bbird81/Netbox-ipscanner) |

---

## Requirements

Add to `local_requirements.txt` in `/opt/netbox`:

```
networkscan
```

> **Note:** `pynetbox` and `ipcalc` are **no longer required** — the script uses the native NetBox Django ORM directly.

---

## Installation

### 1. Install dependency

```bash
sudo /opt/netbox/venv/bin/pip install networkscan
```

### 2. Grant ICMP permissions

`networkscan` uses raw sockets for ICMP pings. The NetBox worker typically runs as non-root user (`netbox`):

| Setup | Command |
|-------|---------|
| **Bare metal** | `sudo setcap cap_net_raw+eip /opt/netbox/venv/bin/python3` |
| **Docker** | Add `--cap-add=NET_RAW` to the container |
| **Alternative** | Replace `networkscan` with a subprocess-based ping (no root needed) |

### 3. Upload the script (recommended for NetBox 4.x)

1. Go to **Automation → Scripts**
2. Click **Upload a script module**
3. Select `netbox_ipscanner.py` and upload
4. The script appears as **IP Scanner** in the list

> **Alternative (legacy):** Copy `netbox_ipscanner.py` to `/opt/netbox/netbox/scripts/` and restart services. UI upload is preferred in NetBox 4.x.

---

## Usage

1. Go to **Automation → Scripts → IP Scanner**
2. Configure options:

   | Variable | Type | Default | Description |
   |----------|------|---------|-------------|
   | `TagBasedScanning` | Boolean | `False` | Enable tag-based scanning |
   | `tag` | String | `scan` | Tag name to filter prefixes |

3. **Uncheck "Commit"** for a dry-run first
4. Click **Run Script**
5. Review the log output, then run again with commit enabled

---

## How it works

For each prefix:
1. **Skip** if tag-based scanning is enabled and the tag is missing
2. **Skip** prefixes with status `Reserved` or `Container`
3. **Skip** IPv6 prefixes (logged as warning)
4. Run `networkscan` ICMP scan
5. Batch-fetch all existing IPs in the prefix (single ORM query via `net_contained_or_equal`)
6. Compare scan results with existing IPs:
   - Present & responding → ensure status = **Active**, update DNS if changed
   - Present & not responding → set status = **Deprecated** (if not already)
   - Absent & responding → create new IPAddress (Active, with DNS)
7. All changes wrapped in `transaction.atomic()` for consistency
8. In dry-run mode (`commit=False`) no writes are performed; actions are logged as `[DRY-RUN]`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Script does not appear in UI | Missing `networkscan` package or import error | Check **System → Jobs** logs; install package & grant rights |
| No hosts found, but ping works | `networkscan` lacks raw-socket capability | Verify `CAP_NET_RAW` is set on the Python interpreter |
| Script fails on a prefix | Invalid or IPv6 prefix in IPAM | Script skips non-IPv4 prefixes with a warning; ensure prefix is valid |
| Timeout on large subnets | Scanning /16+ takes too long | Tag smaller subnets, schedule off-peak, or increase `job_timeout` |

---

## Changelog

### v2.0 — NetBox 4.6.x Migration

> Full rewrite — **breaking changes**, not backwards compatible with NetBox 3.x.

- **Replaced** `pynetbox` REST API with native Django ORM (no token, no HTTP overhead)
- **Fixed** missing imports (`BooleanVar`, `StringVar`) — script now appears in UI
- **Fixed** deprecated `log_error()` → `log_failure()`
- **Added** `transaction.atomic()` for data consistency
- **Added** batch queries via `net_contained_or_equal` — 1 query per prefix instead of N+1
- **Added** proper `commit=False` (dry-run) support
- **Added** IPv6 guard — prefixes safely skipped with warning
- **Added** try/except around `scan.run()` — errors won't crash the whole script
- **Added** UI Upload support (NetBox 4.x native)
- **Added** `job_timeout = 3600` for large scans

### v1.3 — Legacy NetBox 3.7

- Fixed deprecated status filter
- Last version compatible with NetBox 3.7

### v1.2 — Tag Based Scanning

- Added optional tag filter for subnet selection

---

## Upgrade from v1.x (NetBox 3.7 → 4.6)

1. **Remove old file** (if placed on filesystem):
   ```bash
   sudo rm /opt/netbox/netbox/scripts/netbox_ipscanner.py
   ```
2. **Install new dependency**:
   ```bash
   sudo /opt/netbox/venv/bin/pip install networkscan
   ```
3. **Upload via UI** (see Installation above)
4. **Run with dry-run first** — verify the output matches expectations
5. **Remove** `pynetbox` and `ipcalc` from `local_requirements.txt` if no longer needed elsewhere

---

## License

MIT — see the [LICENSE](LICENSE) file.

---

Forked from [bbird81/Netbox-ipscanner](https://github.com/bbird81/Netbox-ipscanner) — original author.
