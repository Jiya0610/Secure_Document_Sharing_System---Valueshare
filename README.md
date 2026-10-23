# VaultShare — Secure Document Sharing

VaultShare is a local-development full-stack project for encrypted document storage, controlled sharing, and activity auditing.

## Run on Windows

Prerequisites: Python 3.10+ and Node.js 20+.

1. In PowerShell, prepare the backend once:

   ```powershell
   cd "D:\projects\secure document sharing\backend"
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Copy-Item .env.example .env   # only if .env does not already exist
   ```

2. Set `FILE_ENCRYPTION_KEY` in `backend/.env` to a 32-byte URL-safe Base64 value. Generate one with:

   ```powershell
   py -c "import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
   ```

   Set a long random `FLASK_SECRET_KEY` too. Keep `.env` safe and never replace it after uploading files; losing the encryption key makes stored files unreadable.

3. Install frontend dependencies once:

   ```powershell
   cd "D:\projects\secure document sharing\frontend"
   npm install
   ```

4. From the project root, run `.\run-dev.ps1`. It opens separate backend and frontend PowerShell windows. Keep both open and visit the Vite `Local` URL (usually `http://localhost:5173`).

## Implemented modules

- **Authentication:** bcrypt password hashing, bearer-token login/logout, email verification, and password reset. In development, the UI exposes a one-time verification or reset link because no mail service is configured.
- **Document management:** private local storage, file type/size validation, searchable document list, encrypted replacement and delete.
- **Security engine:** AES-256-GCM encryption, SHA-256 integrity checks before file access, random nonces, and encryption keys kept outside the database.
- **Sharing:** registered-user view/download permissions, expiration, optional download limits, owner revocation, plus anonymous protected links with hashed tokens, expiry, limits, and revocation.
- **Activity and alerts:** upload, replace, share, view, download, revoke, and failed-access events; notifications for shares and repeated denied access.
- **Dashboard:** document/share counts and recent security-alert count.
- **Database:** SQLite for development with additive migration on startup; set `DATABASE_URL` to use PostgreSQL.

Accepted file types are PDF, DOCX, PNG, JPG/JPEG, and TXT; maximum upload size is 20 MB. Inline preview supports PDF, images, and text. DOCX files can be downloaded when permission allows.

## Production work still required

Development verification/reset links are returned to the local UI. Configure an email provider to send these securely in production. Use HTTPS, a managed database and key service, rate limiting, token expiry/rotation, malware scanning, backups, and monitoring before deployment. A revoked share blocks future access but cannot retrieve copies already downloaded.
