# Explanation of Multi-Device Auth System Changes

[See basic login-register without Multi-Device Management on branch login-register](https://github.com/nottoBD/ssd26-computer-project/blob/webauthn/login-register/README.md)

## Overview
Below is a structured summary of what was incomplete in the previous branch (before setting up a device management) and how to migrate.

## What Was Incomplete/Risky in login-register
- **No Primary Approval for Adds**: Direct registration allowed unauthorized additions (risks: forgery #9, broken auth #14).
- **No Primary-Only Restrictions**: Any device could manage settings/revoke (risks: access control #13, non-repudiation #5).
- **Missing Server Logging/Anomaly Detection**: Client-side only; no metadata logging (risks: monitoring #10, Master note).
- **API Gaps**: 404s on credentials/activity endpoints.
- **Login Usability for New Devices**: Couldn't add from new device without login.
- **Other**: Weak clone checks in approval, potential remanence #8.

## Vision for New System
- **Primary Device Hierarchy**: First device is primary; approves/revokes all changes. Only primary accesses settings.
- **One-Time Code Approval**: Primary generates short-lived code (<10min); new device uses email+code to add as secondary.
- **Per-Device Credentials**: Unique WebAuthn creds per device (PRF keeps shared KEK for E2EE).
- **Logging/Monitoring**: Server logs auth with metadata for anomalies.
- **Best Practices**: FIDO2-compliant, OWASP-aligned, minimal server trust.

## Specific Changes
### Backend Models
- Added `AuthenticationLog`: Logs time/IP/device/success/metadata (#10, Master note).
- Added `User.pending_add_code/expiry`: For secure approvals.

### Backend Views/URLs
- Updated `FinishAuthentication`: Logs attempts, stores credential ID for primary checks, enhanced clone detection.
- Added `is_primary_device`: Restricts sensitive actions.
- Changed Approval/Add: Primary auth generates code; new device uses `/add/start/` with code.
- New Views: `/user/credentials/`, `/user/activity/`, `/credential/<id>/delete/` (primary-only).
- URLs: Added paths for above (fixes 404s).

### Frontend
- Settings: Generate code via primary auth; display for new device. Remove uses new endpoint.
- Login: Add mode for email/code/device_name to join as secondary.

## How to Migrate/Integrate Safely
1. **Apply Models**: Run migrations for new fields/logs.
2. **Update Views/URLs**: Add/replace as provided; existing register/login unchanged.
3. **Update Frontend**: Modify settings/login.tsx; test new URLs (e.g., /api/webauthn/...).
4. **Test Flow**:
   - Register primary.
   - Settings (primary): Generate code.
   - New device login: Add mode, enter email/code.
   - Verify: Secondaries can't manage settings.



## Fix Primary/Secondary

Client/login.txt && Client/settings.tsx: 
- Add credentials: "include" in api call (not all, if other error occurs add to other endpoint)

Server/settings.py : 
- Add CSRF_COOKIE_SECURE = True,CSRF_COOKIE_HTTPONLY = True,CSRF_TRUSTED_ORIGINS = 

Server/webauthn/view.py
- FinishRegistration -> only one primary, add primary if no other device exist and add in session used_credential_id and device_role
- FinishAddCredential -> force secondary device is_primary=False and device_role='secondary'
- StartAddCredentialApproval -> refuse if not primary
- FinishAddCredentialApproval -> fix problem with primary_id bytes or memoryview -> primary_id = primary_id.tobytes()
- StartAddWithCode -> add security by cancel if no primary exist
- is_primary_device() -> better, check is_authenticated and lookup DB