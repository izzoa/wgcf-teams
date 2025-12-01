#!/usr/bin/env python3
"""
wgcf-teams: Extract WireGuard configurations from Cloudflare's WARP for Teams.

This tool registers a device with Cloudflare's Zero Trust API and outputs
a ready-to-use WireGuard configuration file.
"""

import argparse
import base64
import sys
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

API_ENDPOINT = "https://zero-trust-client.cloudflareclient.com/v0i2308311933/reg"
INSTRUCTION_URL = "https://github.com/poscat0x04/wgcf-teams/blob/master/guide.md"

V4_DNS = "1.1.1.1"
V6_DNS = "2606:4700:4700::1111"
WG_MTU = 1420


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate WireGuard config for WARP for Teams"
    )
    parser.add_argument(
        "-p", "--prompt",
        action="store_true",
        help="Prompt for WireGuard private key instead of randomly generating one"
    )
    parser.add_argument(
        "-t", "--token",
        type=str,
        help="JWT token (or path to file containing token)"
    )
    return parser.parse_args()


def generate_private_key() -> X25519PrivateKey:
    """Generate a new X25519 private key."""
    return X25519PrivateKey.generate()


def private_key_to_base64(key: X25519PrivateKey) -> str:
    """Convert X25519 private key to WireGuard base64 format."""
    raw_bytes = key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def public_key_to_base64(key: X25519PrivateKey) -> str:
    """Derive public key and convert to WireGuard base64 format."""
    public_key = key.public_key()
    raw_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def parse_private_key(key_str: str) -> X25519PrivateKey:
    """Parse a WireGuard base64 private key string."""
    try:
        raw_bytes = base64.b64decode(key_str.strip())
        if len(raw_bytes) != 32:
            raise ValueError("Private key must be 32 bytes")
        return X25519PrivateKey.from_private_bytes(raw_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse WireGuard private key: {e}")


def get_or_generate_privkey(prompt: bool) -> X25519PrivateKey:
    """Get private key from user input or generate a new one."""
    if prompt:
        print("Please paste your WireGuard private key and press enter:", file=sys.stderr)
        key_str = input()
        return parse_private_key(key_str)
    else:
        return generate_private_key()


def get_jwt_token(token_arg: str | None) -> str:
    """Get JWT token from argument, file, or interactive prompt."""
    if token_arg:
        # Check if it's a file path
        import os
        if os.path.isfile(token_arg):
            with open(token_arg, "r") as f:
                token = f.read().strip()
            print(f"Token loaded from file ({len(token)} chars)", file=sys.stderr, flush=True)
            return token
        else:
            # Assume it's the token itself
            print(f"Token provided via argument ({len(token_arg)} chars)", file=sys.stderr, flush=True)
            return token_arg.strip()
    
    # Interactive prompt
    print("\n" + "="*70, file=sys.stderr, flush=True)
    print("JWT Token Required", file=sys.stderr, flush=True)
    print("="*70, file=sys.stderr, flush=True)
    print("\nTo get your JWT token:", file=sys.stderr, flush=True)
    print("  1. Open https://<YOUR_ORGANIZATION>.cloudflareaccess.com/warp", file=sys.stderr, flush=True)
    print("  2. Log in with your organization credentials", file=sys.stderr, flush=True)
    print("  3. Open Developer Tools (F12) → Application → Cookies", file=sys.stderr, flush=True)
    print("  4. Copy the value of the 'CF_Authorization' cookie", file=sys.stderr, flush=True)
    print(f"\nFor detailed instructions: {INSTRUCTION_URL}", file=sys.stderr, flush=True)
    print("\n" + "-"*70, file=sys.stderr, flush=True)
    print("Paste your JWT token below and press Enter:", file=sys.stderr, flush=True)
    print("> ", end="", file=sys.stderr, flush=True)
    # Use readline directly to handle long tokens better
    token = sys.stdin.readline().strip()
    if not token:
        raise ValueError("No token provided")
    print(f"Token received ({len(token)} chars)", file=sys.stderr, flush=True)
    return token


def build_session() -> requests.Session:
    """Build an HTTP session with headers mimicking the WARP iOS client."""
    session = requests.Session()
    session.headers.update({
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "CF-Client-Version": "i-6.23-2308311933.1",
        "User-Agent": "1.1.1.1/6.23",
    })
    return session


def register_device(privkey: X25519PrivateKey, token: str) -> dict:
    """Register device with Cloudflare's Zero Trust API."""
    session = build_session()
    
    # Build registration payload
    pubkey = public_key_to_base64(privkey)
    payload = {
        "key": pubkey,
        "tos": datetime.now(timezone.utc).isoformat(),
        "model": "iPad13,8",
        "fcm_token": "",
        "device_token": "",
    }
    
    print("Registering device with Cloudflare...", file=sys.stderr, flush=True)
    
    # Make registration request
    response = session.post(
        API_ENDPOINT,
        json=payload,
        headers={"Cf-Access-Jwt-Assertion": token},
        timeout=30
    )
    
    print(f"Response status: {response.status_code}", file=sys.stderr, flush=True)
    
    data = response.json()
    
    if not data.get("success") or data.get("result") is None:
        errors = data.get("errors", [])
        messages = data.get("messages", [])
        error_msg = "Request to Cloudflare API failed.\n"
        if errors:
            error_msg += f"Errors: {errors}\n"
        if messages:
            error_msg += f"Messages: {messages}\n"
        raise RuntimeError(error_msg)
    
    return data["result"]


def build_wireguard_config(privkey: X25519PrivateKey, result: dict) -> str:
    """Build WireGuard configuration string from API response."""
    config = result["config"]
    
    # Extract routing ID (base64 decode client_id to get 3 bytes)
    client_id_b64 = config["client_id"]
    client_id_bytes = base64.b64decode(client_id_b64)
    routing_id_hex = client_id_bytes[:3].hex()
    
    # Extract peer info
    peer = config["peers"][0]
    peer_pubkey = peer["public_key"]
    endpoint = peer["endpoint"]["host"]
    
    # Extract interface addresses
    addresses = config["interface"]["addresses"]
    v4_addr = addresses["v4"]
    v6_addr = addresses["v6"]
    
    # Build config string
    privkey_b64 = private_key_to_base64(privkey)
    
    lines = [
        f"# routing-id: 0x{routing_id_hex}",
        "[Interface]",
        f"PrivateKey = {privkey_b64}",
        f"Address = {v6_addr}/128",
        f"Address = {v4_addr}/32",
        f"DNS = {V4_DNS}",
        f"DNS = {V6_DNS}",
        f"MTU = {WG_MTU}",
        "",
        "[Peer]",
        f"PublicKey = {peer_pubkey}",
        "AllowedIPs = ::/0",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {endpoint}",
    ]
    
    return "\n".join(lines)


def main():
    """Main entry point."""
    args = parse_args()
    
    try:
        privkey = get_or_generate_privkey(args.prompt)
        token = get_jwt_token(args.token)
        result = register_device(privkey, token)
        config = build_wireguard_config(privkey, result)
        
        # Print to terminal
        print(config)
        
        # Write to output.conf
        with open("output.conf", "w") as f:
            f.write(config)
            f.write("\n")
        print("\nConfig written to output.conf", file=sys.stderr, flush=True)
        
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

