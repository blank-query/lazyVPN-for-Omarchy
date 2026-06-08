# Supported VPN Providers

## Support Criteria

A provider is supported in lazyVPN when **all three** of these are true:

1. **Listed in [gluetun's servers.json](https://github.com/qdm12/gluetun/blob/master/internal/storage/servers.json) with WireGuard entries.** lazyVPN reads this file to populate the dynamic server browser. Providers whose gluetun entry is OpenVPN-only are not usable via dynamic browsing.
2. **Supports WireGuard.** lazyVPN does not ship OpenVPN.
3. **User can obtain a WireGuard config.** Either download a `.conf` from the provider's member area, or otherwise extract the private key + endpoint. Setup requires one config file.

---

## Verified

Tested end-to-end on a real account.

| Provider  | Free tier | Notes                          |
|-----------|-----------|--------------------------------|
| ProtonVPN | yes       | Reference provider for testing |

## Experimental

Meets all three criteria and is wired into lazyVPN, but hasn't been personally verified yet. Should work. [Please report results](https://github.com/blank-query/lazyVPN-for-Omarchy/issues) if you try one of these.

| Provider    | Gluetun WG servers | Notes                                     |
|-------------|--------------------|-------------------------------------------|
| NordVPN     | 5421               |                                           |
| Mullvad     |  562               |                                           |
| AirVPN      |  510               |                                           |
| Windscribe  |  390               |                                           |
| Surfshark   |  178               |                                           |
| IVPN        |   84               |                                           |
| FastestVPN  |   70               | DNS (`10.8.0.1`) inferred, not verified.  |

## Unsupported

Anything not listed above is unsupported. Reasons are specific — some providers fail multiple criteria.

| Provider          | Fails | Reason                                                                 |
|-------------------|-------|------------------------------------------------------------------------|
| PIA               | #1,#3 | In gluetun but **0 WireGuard entries** (OpenVPN only). No downloadable `.conf` — their WireGuard credentials are generated per-session via a token API. |
| ExpressVPN        | #2    | Uses proprietary Lightway protocol; no native WireGuard.               |
| CyberGhost        | #1    | In gluetun, 0 WireGuard entries.                                       |
| IPVanish          | #1    | In gluetun, 0 WireGuard entries.                                       |
| TorGuard          | #1    | In gluetun, 0 WireGuard entries.                                       |
| VyprVPN           | #1    | In gluetun, 0 WireGuard entries.                                       |
| Perfect Privacy   | #1    | In gluetun, 0 WireGuard entries.                                       |
| PrivateVPN        | #1    | In gluetun, 0 WireGuard entries.                                       |
| PureVPN           | #1    | In gluetun, 0 WireGuard entries.                                       |
| HideMyAss         | #1    | In gluetun, 0 WireGuard entries.                                       |
| Privado           | #1    | In gluetun, 0 WireGuard entries.                                       |
| SlickVPN          | #1    | In gluetun, 0 WireGuard entries.                                       |
| VPN Unlimited     | #1    | In gluetun, 0 WireGuard entries.                                       |
| VPNSecure         | #1    | In gluetun, 0 WireGuard entries.                                       |
| Giganews          | #1    | In gluetun, 0 WireGuard entries (Usenet service, VPN is bundled).      |

