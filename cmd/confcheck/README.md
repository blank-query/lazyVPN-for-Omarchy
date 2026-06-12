# confcheck — LazyVPN config validator

A standalone diagnostic that explains, in plain English, why a WireGuard `.conf`
does or doesn't validate under LazyVPN's **exact** rules — it calls LazyVPN's own
`ParseConfig` / `Validate` / `ValidatePrivateKey`, so the verdict matches what
LazyVPN's "Set Up Provider" / "Import WireGuard Config" would decide.

It also reports whether the config's **provider is supported by the dynamic
server browser** (using LazyVPN's exact detection). For a valid config whose
provider isn't supported, it explains that the config still works via manual
import but can't be browsed dynamically (its servers aren't in the gluetun data
LazyVPN mirrors).

**It prints no secrets.** No private/preshared/public keys, no endpoint, address,
or DNS *values* are ever shown — only which fields are present, whether keys
decode, their byte lengths, the detected provider id, and the verdict. The
output is safe to paste into a bug report.

## Use it — no build needed

A prebuilt static `linux/amd64` binary is committed on this branch:

```bash
curl -fL -o confcheck https://github.com/blank-query/lazyVPN-for-Omarchy/raw/conf-validator/confcheck
chmod +x confcheck
./confcheck /path/to/your.conf
```

## Or build from source (Go 1.25+)

```bash
go build -o confcheck ./cmd/confcheck
./confcheck /path/to/your.conf
```

## Example

```
$ ./confcheck broken.conf
LazyVPN config validator (confcheck)
Same rules as LazyVPN. No secrets are printed — safe to share.
====================================================================
Structure (redacted — no key/endpoint/address/DNS values are printed):
  [Interface] section        found
    PrivateKey               present, but base64 decode FAILED (illegal base64 data at input byte 3)
    ...
--------------------------------------------------------------------
Verdict — LazyVPN's actual parse + validate:
  ✗ REJECTED at parse: invalid PrivateKey: illegal base64 data at input byte 3
    → The [Interface] PrivateKey isn't standard padded base64. ...
```

This branch is a diagnostic side-branch and is not part of any release.
