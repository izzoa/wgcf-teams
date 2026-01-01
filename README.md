# wgcf-teams

Generate WireGuard configuration files for Cloudflare WARP for Teams (Zero Trust).

This tool registers a device with Cloudflare's Zero Trust API and outputs a ready-to-use WireGuard configuration, allowing you to use any WireGuard client instead of the official WARP client.

## Requirements

- Python 3.10+
- A Cloudflare Zero Trust organization

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Get your JWT token

1. Open `https://<YOUR_ORGANIZATION>.cloudflareaccess.com/warp` in your browser
2. Log in with your organization credentials
3. After successful login, open browser Developer Tools (F12)
4. Go to **Application** → **Cookies**
5. Find the cookie named `CF_Authorization` and copy its value

### 2. Generate WireGuard config

**Option A: Pass token via command line**

```bash
python wgcf_teams.py -t "YOUR_JWT_TOKEN"
```

**Option B: Pass token from file**

```bash
echo "YOUR_JWT_TOKEN" > token.txt
python wgcf_teams.py -t token.txt
```

**Option C: Interactive prompt**

```bash
python wgcf_teams.py
# Paste your token when prompted
```

### 3. Output

The tool will:
- Print the WireGuard configuration to stdout
- Save it to `output.conf` in the current directory

### CLI Options

| Option | Description |
|--------|-------------|
| `-t`, `--token` | JWT token or path to file containing the token |
| `-p`, `--prompt` | Prompt for an existing WireGuard private key instead of generating a new one |

## Example Output

```ini
# routing-id: 0xabc123
# reserved bytes: [171, 193, 35]
# NOTE: Standard WireGuard doesn't support 'reserved' field!
# You need a compatible client (Xray-core, Amnezia, warp.sh, etc.)
[Interface]
PrivateKey = <generated-private-key>
Address = 2606:4700:xxx:xxxx::x/128, 100.96.x.x/32
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25
```

> **Important:** Standard WireGuard clients do not support the `reserved` bytes required by Cloudflare WARP. You must use a compatible client that supports this field, such as:
> - [Xray-core](https://github.com/XTLS/Xray-core)
> - [Amnezia VPN](https://amnezia.org/)
> - [warp.sh](https://gitlab.com/fscarmen/warp)

## Troubleshooting

### WireGuard tunnel doesn't connect

1. **Check endpoint resolution**: Ensure `engage.cloudflareclient.com` resolves properly
2. **Firewall**: UDP port 2408 must be open outbound
3. **IPv6**: If your network lacks IPv6, remove the IPv6 address and `::/0` from AllowedIPs
4. **Token expiry**: JWT tokens expire quickly - generate a fresh one if needed

### Verify handshake

```bash
# Linux/OpenWRT
wg show

# Look for "latest handshake" - if missing, no connection was established
```

## License

BSD-3-Clause
