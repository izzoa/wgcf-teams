# How to Get Your JWT Token for WARP for Teams

This guide will walk you through finding your JWT token from Cloudflare WARP for Teams, which is required to generate a WireGuard configuration.

## Prerequisites

- Access to a Cloudflare Zero Trust organization
- A web browser with Developer Tools enabled
- Your organization login credentials

## Step-by-Step Instructions

### Step 1: Navigate to WARP for Teams

1. Open your web browser
2. Navigate to: `https://<YOUR_ORGANIZATION>.cloudflareaccess.com/warp`
   - Replace `<YOUR_ORGANIZATION>` with your actual Cloudflare organization name
   - Example: `https://mycompany.cloudflareaccess.com/warp`

### Step 2: Log In

1. Enter your organization credentials when prompted
2. Complete any required authentication steps (e.g., SSO, 2FA)
3. Wait for the page to fully load after successful login

### Step 3: Open Developer Tools

**For Chrome/Edge/Brave:**
- Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
- Or right-click anywhere on the page → Select "Inspect"

**For Firefox:**
- Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
- Or right-click → Select "Inspect Element"

**For Safari:**
- First enable Developer menu: Safari → Preferences → Advanced → Check "Show Develop menu"
- Then press `Cmd+Option+I` or Develop → Show Web Inspector

### Step 4: Navigate to Cookies

1. In the Developer Tools panel, look for the following tabs at the top:
   - **Chrome/Edge/Brave**: Click on the **"Application"** tab
   - **Firefox**: Click on the **"Storage"** tab
   - **Safari**: Click on the **"Storage"** tab

2. In the left sidebar, expand the **"Cookies"** section
3. Click on the domain: `https://<YOUR_ORGANIZATION>.cloudflareaccess.com`

### Step 5: Find and Copy the JWT Token

1. In the cookies list, look for a cookie named **`CF_Authorization`**
2. Click on the `CF_Authorization` cookie to select it
3. Look at the **"Value"** field - this is your JWT token
4. The token will be a long string starting with something like `eyJ...` (it's a base64-encoded JWT)
5. **Copy the entire value** - you can:
   - Double-click the value field and press `Ctrl+C` / `Cmd+C`
   - Right-click the value → Copy
   - Select the entire value and copy it

### Step 6: Use the Token

You can now use this token with `wgcf-teams`:

```bash
# Option 1: Interactive mode (paste when prompted)
python wgcf_teams.py

# Option 2: Command line argument
python wgcf_teams.py -t "YOUR_JWT_TOKEN_HERE"

# Option 3: From a file
echo "YOUR_JWT_TOKEN_HERE" > token.txt
python wgcf_teams.py -t token.txt
```

## Important Notes

⚠️ **Token Expiration**: JWT tokens expire quickly (usually within minutes). If you get an error, generate a fresh token by repeating these steps.

⚠️ **Security**: Never share your JWT token publicly. It provides access to your organization's WARP network.

⚠️ **Token Format**: The token should be a long string (typically 200+ characters). If it looks too short, you may have copied only part of it.

## Troubleshooting

### Can't find the CF_Authorization cookie

- **Make sure you're logged in**: The cookie only appears after successful authentication
- **Check the correct domain**: Ensure you're looking at cookies for `*.cloudflareaccess.com`
- **Try refreshing**: Sometimes you need to refresh the page after login
- **Clear and retry**: If cookies aren't showing, try clearing browser cache and logging in again

### Token doesn't work

- **Token expired**: Generate a fresh token (they expire quickly)
- **Incomplete copy**: Make sure you copied the entire token value, including the beginning (`eyJ`) and end
- **Extra whitespace**: Ensure there are no spaces before or after the token when pasting

### Developer Tools won't open

- **Keyboard shortcuts**: Try the alternative methods (right-click → Inspect)
- **Browser permissions**: Some browsers require enabling Developer Tools in settings
- **Private/Incognito mode**: Developer Tools work in private browsing, but cookies may behave differently

## Visual Guide

While we can't include screenshots here, the general layout in Developer Tools should look like this:

```
Developer Tools
├── Application (or Storage) tab
    └── Cookies
        └── https://yourorg.cloudflareaccess.com
            ├── CF_Authorization  ← This is what you need!
            ├── Other cookies...
            └── ...
```

The `CF_Authorization` cookie's value field contains your JWT token.

## Need More Help?

If you continue to have issues:
1. Verify you have access to WARP for Teams in your organization
2. Contact your organization's IT administrator
3. Check the [main README](../README.md) for additional troubleshooting

