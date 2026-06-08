# LazyVPN server data

This is a **data-only branch** — it has no shared history with `master` and contains
no application code. It holds per-provider WireGuard server snapshots that the LazyVPN
binary fetches at runtime (under its dynamic-server browser).

## What's here

One file per supported provider (`protonvpn.json`, `mullvad.json`, …), each in the form:

```json
{ "version": 4, "servers": [ { "server_name": "...", "hostname": "...", "wgpubkey": "...", "ips": ["..."], ... } ] }
```

Only WireGuard servers are kept; OpenVPN entries are filtered out.

## How it's updated

These files are regenerated weekly by the `update-servers` GitHub Action (on `master`),
which pulls the latest data from the [gluetun-servers](https://github.com/qdm12/gluetun-servers)
project, WireGuard-filters it, and commits the result here. The app fetches from this
branch — not from gluetun directly — so if upstream ever moves or removes its data, only
this repository's update job is affected; released binaries keep working off the last
snapshot committed here.

Server data is derived from [gluetun-servers](https://github.com/qdm12/gluetun-servers)
(MIT License, © Quentin McGaw).
