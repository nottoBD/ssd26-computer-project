## User Management

- **Credential/Info Changes (Master Note)**: Implement PUT `/api/users/credentials` for updating WebAuthn credentials or certs. Client generates new keypair, signs update request; server revokes old cert via CRL update in PKI (using oscrypto or similar for CRL management). Support multi-device: broadcast changes to approved devices via WebSocket (ws module), require secondary approval if primary initiates.

- **Revocation**: Add DELETE `/api/users/revoke` endpoint. Client signs revocation; server marks user inactive, adds cert to CRL, cascades to remove from appointed lists (atomic transaction with mongoose-transactions). Prevent access to records post-revocation by checking CRL on every request.

## Doctor Appointment Management

- **Add/Remove Doctors**: For patient-initiated: POST/DELETE `/api/appointments/doctor/:doctorId` from client, signed by patient cert. Server verifies sig, updates patient's encrypted appointedDoctors array (decrypt not needed; use blinded index for doctor ID search). Sanitize :doctorId with express-validator to prevent Mongo injection.

- **Doctor-Initiated Appointments**: POST `/api/appointments/request/:patientId` from doctor client, signed. Server stores pending request in temp collection, notifies patient via email (nodemailer) or push (if implemented). Patient approves via PUT `/api/appointments/approve/:requestId`, signing approval; server then updates lists. Use uuid for requestId to avoid guessable IDs.

- **Integrity/Non-Repudiation**: Chain appointment history with hashes (previousHash field in schema), verify on read to detect tampering. Use helmet middleware for CSP/XSS protection on related endpoints.

## Medical Record Management

- **Record Structure**: Model in `server/models/record.js` as tree: Patient has root Record doc with files array (each: encryptedContent as Binary, encryptedName as string, date as Date, signatures array). Support directory depth up to 5 (config const); store treeDepth in metadata. No subdirs enforced, but allow nested via parentId refs.

- **Viewing Records**: GET `/api/records/:patientId` (for self or appointed doctor). Server checks caller cert against appointed list (blinded query), sends encrypted files. Client decrypts/verifies sigs. For doctors, require re-auth if session >1h (using express-session with secure cookies).

- **Uploading Files**: POST `/api/records/upload` using multer (diskStorage with uuid filenames, limits: {fileSize: 10*1024*1024}, fileFilter: validate MIME with file-type module to allow pdf/docx/jpg/png only, reject others to prevent shell injections). Client encrypts file/content/date/name, signs; server stores, adds to tree. Sandbox uploads: process in /tmp dir, use fs.promises.unlink post-upload. For doctor-initiated: require patient approval via signed token (JWT with jose module, short expiry).

- **Editing Files**: PUT `/api/records/:fileId` similar to upload, but append version (use mongoose-version plugin for auto-versioning). Client re-encrypts new content, signs; server replaces, preserves old version hash for audit.

- **Deleting Files**: DELETE `/api/records/:fileId`, signed by patient/approved doctor. Server marks as deleted (soft delete with isDeleted flag), overwrites content with zeros (via node:crypto randomBytes) to mitigate remanence. Ensure non-repudiation by logging signed delete request immutably.

- **Doctor Actions Approval**: For upload/edit/delete by doctor, create pendingAction doc, patient approves via multi-device flow (poll endpoint or WebSocket). Use rate-limit on approvals to prevent spam.

- **Key Rotation**: Implement PUT `/api/records/rotate-key` for per-patient symmetric key rotation to limit breach impact. Each patient's records use a unique symmetric key, derived via PBKDF2 from their WebAuthn credential (or cert passphrase) + salt. Store encrypted key metadata (e.g., version, creation date) on server as blinded index. Client generates new AES-GCM 256-bit key (crypto.subtle.generateKey), optionally re-encrypts existing files in batches (download, decrypt with old, encrypt with new, re-upload). Share new key with appointed doctors via ECDH (from X.509 certs) for secure wrap (crypto.subtle.wrapKey). Trigger manually or auto (every 90 days, timestamp check on login). Require multi-device approval. Retain old keys client-side in IndexedDB for historical decryption; purge after full re-encryption.
