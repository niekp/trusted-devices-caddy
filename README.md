# Trusted Devices Caddy Plugin

This Caddy plugin enforces trusted devices based on IP addresses and tokens. Devices that connect from trusted IPs receive a cookie with a token, allowing them to remain trusted for up to 1 year even when connecting from untrusted IPs.

## Features

- Maintains a list of trusted IP addresses in a file.
- Stores trusted tokens (with expiry) in a JSON file.
- Sets a cookie for devices connecting from trusted IPs.
- Validates existing cookies to allow access without needing a trusted IP.
- Configurable cookie name and max age.

## Installation

### Prerequisites

- Go 1.21 or later
- xcaddy (for building Caddy with plugins)

Install xcaddy if not already installed:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### Building

#### Option 1: Using caddy add-package (Recommended for Installation)

If you have Caddy installed, add the plugin directly:

```bash
sudo caddy add-package github.com/niekp/trusted-devices-caddy
```

This will download and integrate the plugin into your Caddy installation.

#### Option 2: Building from Source

Clone this repository:

```bash
git clone https://github.com/niekp/trusted-devices-caddy.git
cd trusted-devices-caddy
```

Build Caddy with the plugin:

```bash
xcaddy build --with .
```

For cross-compilation (e.g., for Linux AMD64 from macOS):

```bash
xcaddy build --with . --os linux --arch amd64 --output caddy-server
```

Alternatively, using go build (requires a separate main file):

```bash
# Not directly applicable since this is a plugin module
```

## Usage

### Configuration

Add the plugin to your Caddyfile:

```
{
    http_port 80
    https_port 443
}

example.com {
    trusted_devices {
        trusted_ips_file "/path/to/trusted_ips.txt"
        trusted_tokens_file "/path/to/trusted_tokens.json"
        cookie_name "trusted_device"
        max_age "8760h"  # 1 year
    }
    # Other directives...
    reverse_proxy localhost:8080
}
```

### Files

- **trusted_ips.txt**: A text file with one trusted IP address per line.
  ```
  192.168.1.100
  10.0.0.1
  ```

- **trusted_tokens.json**: Automatically managed JSON file storing tokens and their expiry times. Do not edit manually.

### How It Works

1. When a request comes from a trusted IP:
   - If no valid cookie is present, a new token is generated, stored, and sent as a cookie.
   - The device is allowed access.

2. When a request has a valid cookie (token exists and not expired):
   - Access is granted, regardless of IP.

3. Otherwise, access is denied with a 403 Forbidden response.

## Debugging

### Local Testing

1. Build the plugin as above.

2. Create sample files:
   - `trusted_ips.txt` with your local IP or `127.0.0.1`.
   - `trusted_tokens.json` can be empty initially.

3. Create a simple Caddyfile:

   ```
   :8080 {
       trusted_devices {
           trusted_ips_file "trusted_ips.txt"
           trusted_tokens_file "trusted_tokens.json"
       }
       respond "Hello, trusted device!"
   }
   ```

4. Run Caddy:

   ```bash
   ./caddy run --config Caddyfile
   ```

5. Test:
   - From a trusted IP: `curl http://localhost:8080` should work and set a cookie.
   - From an untrusted IP: Should return 403.
   - With the cookie: `curl -b "trusted_device=<token>" http://localhost:8080` should work.

### Logs

Enable debug logging in Caddy:

```bash
./caddy run --config Caddyfile --log-level debug
```

Check logs for plugin behavior.

### Common Issues

- **403 Forbidden**: Ensure your IP is in `trusted_ips.txt` or you have a valid cookie.
- **File permissions**: Ensure Caddy can read/write the token file.
- **IP detection**: If behind a proxy, ensure `X-Forwarded-For` or `X-Real-IP` headers are set correctly.

## Deployment

For production deployment:

1. Build the binary for your server's architecture.
2. Transfer the binary, Caddyfile, and `trusted_ips.txt` to the server.
3. Run Caddy as a service (e.g., via systemd).

Example systemd service:

```ini
[Unit]
Description=Caddy Web Server
After=network.target

[Service]
User=caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
Restart=always

[Install]
WantedBy=multi-user.target
```

## License

MIT License
