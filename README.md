# Trusted Devices Caddy Plugin

A Caddy plugin that restricts access to trusted devices based on IP addresses and secure tokens. Devices from trusted IPs receive a persistent cookie, allowing continued access even when connecting from different locations.

Great for web-applications that you want to access outside of your network also. Login once on your trusted network so your device gets a cookie and now the site works everywhere.

## Features

- IP-based access control with file-based configuration, single addresses or CIDR ranges
- Automatic token generation and persistent cookie creation
- Configurable token expiration (default: 1 year)
- Automatic cleanup of expired tokens on startup and periodically while running
- Support for comments in the IP list file

## Security model

Access is granted when **either** of these holds:

1. The request comes from a trusted IP (which then mints a long-lived cookie), or
2. The request carries a valid token cookie.

The client IP is taken from Caddy's resolved `client_ip`, **not** from raw
`X-Forwarded-For` / `X-Real-IP` headers. Those headers are attacker-controlled;
trusting them directly would let anyone spoof a trusted IP. Caddy only honors
forwarding headers for hops you explicitly mark as trusted.

> ⚠️ **If Caddy sits behind another proxy** (Cloudflare, nginx, a load balancer),
> you **must** configure [`trusted_proxies`](https://caddyserver.com/docs/caddyfile/options#trusted-proxies)
> in the global options. Without it, Caddy treats the proxy's address as the
> client IP, so no real client IP will ever match your trusted list. With it
> configured, only forwarding headers added by that trusted proxy are honored.

Tokens are 122-bit random UUIDs and are stored in a `0600` file written
atomically. User-Agent strings are **not** used for access decisions — they are
trivially forgeable and not secret.

## Doesn't support (yet)

- Applications that need to be accessed outside of the webbrowser, like home assistent, music servers, ...
- Granting access with a special header
- Granting access with a simple password

## Installation

### Using xcaddy (Recommended)

```bash
xcaddy build --with github.com/niekp/trusted-devices-caddy
```

For multiple plugins:
```bash
xcaddy build \
  --with github.com/niekp/trusted-devices-caddy \
  # --with other-plugin
```

### Using caddy add-package

```bash
sudo caddy add-package github.com/niekp/trusted-devices-caddy
```

## Configuration

### Basic Usage

```caddyfile
{
    order trusted_devices before authenticate
}

example.com {
    trusted_devices {
        trusted_ips_file "/etc/caddy/trusted_ips.txt"
        trusted_tokens_file "/var/lib/caddy/trusted_tokens.json"
        cookie_name "trusted_device"
        max_age "8760h"
    }
    reverse_proxy localhost:8080
}
```

### Shared Configuration

Use snippets to reuse configuration across multiple sites:

```caddyfile
{
    order trusted_devices before authenticate
}

(trusted_devices_config) {
    trusted_devices {
        trusted_ips_file "/etc/caddy/trusted_ips.txt"
        trusted_tokens_file "/var/lib/caddy/trusted_tokens.json"
        cookie_name "trusted_device"
        max_age "8760h"
    }
}

*.example.com {
    @site1 host site1.example.com
    handle @site1 {
         import trusted_devices_config
         reverse_proxy localhost:8080
    }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `trusted_ips_file` | Path to file with trusted IP addresses or CIDR ranges (one per line) | `trusted_ips.txt` |
| `trusted_tokens_file` | Path to JSON file storing tokens (auto-created) | `trusted_tokens.json` |
| `cookie_name` | Name of the authentication cookie | `trusted_device` |
| `max_age` | Token validity duration | `8760h` (1 year) |

### File Format

**trusted_ips.txt**:
```
# One device
192.168.1.100
# A whole network
10.0.0.0/24
# IPv6 works too
2001:db8:1234::/64
```

Lines that are neither an address nor a range are skipped with a warning in the log. A range with host bits set (`10.0.0.5/24`) trusts the whole range (`10.0.0.0/24`), and `/0` trusts every address; both are logged as a warning too, since they're usually a typo.

**trusted_tokens.json** (auto-managed):
```json
{
  "a1b2c3d4-...": "2026-12-19T14:30:00Z"
}
```

## How It Works

1. **Trusted IP Access**: Request from trusted IP → allows access; when it's a page load in a browser (`Sec-Fetch-Mode: navigate`, or a GET for HTML from a browser without fetch metadata), it also generates a token and sets the cookie
2. **Token Validation**: Request with valid cookie → allows access (any IP)
3. **Denied Access**: No valid cookie and not a trusted IP → 403 Forbidden

Only browsers get a token, on a page load. Apps and scripts on a trusted IP are let through there but get no cookie, so they can't reach the site from elsewhere; this plugin is for websites opened in a browser (see *Doesn't support*).

## Troubleshooting

### Tokens Not Persisting

**Error**: `"failed to save token","error":"...read-only file system"`

**Solution**: Use a writable directory for tokens:
```bash
sudo mkdir -p /var/lib/caddy
sudo chown caddy:caddy /var/lib/caddy
```

Update Caddyfile to use `/var/lib/caddy/trusted_tokens.json`.

### Access Denied (403)

- Verify your IP is in `trusted_ips.txt`
- Check logs: `sudo journalctl -u caddy -f | grep trusted_devices`
- Behind a proxy? Configure `trusted_proxies` in Caddy's global options (see [Security model](#security-model)). Without it, Caddy never resolves the real client IP and every request is denied.

### Directive Not Recognized

**Error**: `unrecognized directive: trusted_devices`

**Solution**: Rebuild Caddy with the plugin and ensure the binary is deployed to the server.

### Debugging

Enable debug logging to see detailed token operations:
```bash
caddy run --config /etc/caddy/Caddyfile --log-level debug
```

Look for logs containing:
- `"loaded trusted IPs"` - confirms IP file loaded
- `"loaded trusted tokens"` - confirms existing tokens loaded
- `"saved tokens to file"` - confirms token persistence

## License

MIT License
