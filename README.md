# WebAuthn Login & Register System

[See basic commands in skeleton-index README](https://github.com/nottoBD/ssd26-computer-project/blob/skeleton-index/README.md)

## Prerequisites

**Important**: Password managers (like Bitwarden) refuse to create passkeys for `localhost` due to security reasons. You must configure a local domain for testing.

### Step 1: Configure Local Domain
Add this entry to your `/etc/hosts` file:

```bash
# Static table lookup for hostnames
# See hosts(5) for details
127.0.0.1        healthsecure.local
::1              localhost
```

## Access Registration

Navigate to: https://healthsecure.local/register

**Note**: While `https://localhost` remains accessible, passkey registration and login will not function through this address.

## Current Status

### ✅ Login & Registration
- Fully functional with passkeys when using `healthsecure.local`
- Bitwarden example: https://pasteboard.co/ggYuNqiRSJFM.png
- Any additional device can login with a password manager
- No password
- No account recovery
- No multidevice with primary/secondary system (yet!)

### Current Issues
- Must fix dependency problems client's CryptoUtils.ts and vite.config.ts...

## Future Integration
- Full PKI implementation will follow after resolving login & multi-device access
- This will eliminate the need for `/etc/hosts` modification

