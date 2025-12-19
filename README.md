# Trusted Devices Caddy Plugin

A Caddy plugin that restricts access to trusted devices based on IP addresses and secure tokens. Devices from trusted IPs receive a persistent cookie, allowing continued access even when connecting from different locations.

## Features

- IP-based access control with file-based configuration
- Automatic token generation and persistent cookie creation
- Configurable token expiration (default: 1 year)
- Automatic cleanup of expired tokens on startup
- Support for comments in IP list files
- Comprehensive logging for debugging

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
        route {
            import trusted_devices_config
            reverse_proxy localhost:8080
        }
    }
}
```

**Important**: Use `route` blocks inside `handle` directives to preserve handler ordering.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `trusted_ips_file` | Path to file with trusted IP addresses (one per line) | `trusted_ips.txt` |
| `trusted_tokens_file` | Path to JSON file storing tokens (auto-created) | `trusted_tokens.json` |
| `cookie_name` | Name of the authentication cookie | `trusted_device` |
| `max_age` | Token validity duration | `8760h` (1 year) |

### File Format

**trusted_ips.txt**:
```
# Home network
192.168.1.100
# Office
10.0.0.1
```

**trusted_tokens.json** (auto-managed):
```json
{
  "a1b2c3d4-...": "2026-12-19T14:30:00Z"
}
```

## How It Works

1. **Trusted IP Access**: Request from trusted IP → generates token → sets cookie → allows access
2. **Token Validation**: Request with valid cookie → allows access (any IP)
3. **Denied Access**: No valid cookie or trusted IP → 403 Forbidden

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
- Behind a proxy? Ensure `X-Forwarded-For` or `X-Real-IP` headers are forwarded

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

## Production Deployment

1. Build for your target architecture:
   ```bash
   xcaddy build --with github.com/niekp/trusted-devices-caddy --os linux --arch amd64
   ```

2. Set up directories with proper permissions:
   ```bash
   sudo mkdir -p /var/lib/caddy /etc/caddy
   sudo chown caddy:caddy /var/lib/caddy
   sudo chmod 755 /var/lib/caddy /etc/caddy
   ```

3. Deploy files:
   - Caddy binary → `/usr/local/bin/caddy`
   - Caddyfile → `/etc/caddy/Caddyfile`
   - trusted_ips.txt → `/etc/caddy/trusted_ips.txt`

4. Run as systemd service (Caddy's default service file works without modification)

## License

MIT License
