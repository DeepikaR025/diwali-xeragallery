# Xerago Diwali Moments (Node.js)

QR → employee sign-in → festive camera with the stamp frame → preview → post → gallery → vote.
Includes a separate **admin console** (email allowlist + one-time code, approve/reject, ZIP export, QR expiry, uploader ID/department).

## Quick start
```bash
npm install
cp .env.example .env        # then edit values (set SESSION_SECRET!)
npm start                   # http://localhost:3000
npm test                    # 35-check end-to-end smoke test
```
- Employee site: `/`  ·  QR target: `/scan`  ·  Admin console: `/admin` (change with `ADMIN_PATH`)
- With no SMTP configured, admin login codes are printed in the server console. Set `DEV_SHOW_CODE=true` (development only) to also see them on screen.

## What is real in this version
| Area | Behaviour |
|---|---|
| Employee sign-in | Name + employee ID + department; optional allowlist (`EMPLOYEE_ALLOWLIST=true` + `data/employees.json`); signed httpOnly cookie; "remember me" = 30 days |
| Photos | PNG uploaded to `data/photos`, validated (type, size), max 3 per employee, delete frees a slot |
| Gallery | Others' approved photos only; own photos on top with status label; heart vote toggles, one vote per photo, no self-vote; report hides photo immediately |
| Admin sign-in | Only emails in the admin list; 6-digit code (10 min, 5 tries); sessions re-checked every request, so revoking is instant |
| Admin console | All photos with name / employee ID / department, filters, approve / reject / restore, ZIP + manifest.csv, auto-publish switch, voting switch, activity log |
| QR | Generated server-side (`/api/admin/qr.png`), points to `/scan`; expire now or on a schedule — enforced on the server for scans, sign-ins and uploads |
| Super admin | Grants / revokes admin emails (`SUPER_ADMIN_EMAIL`) |

## Before going live
1. Host behind **HTTPS** (needed for camera access) and set `NODE_ENV=production`, `BASE_URL`, a long `SESSION_SECRET`, and SMTP settings.
2. Replace the demo name+ID check with company SSO (Azure AD / Google Workspace) or enable the allowlist.
3. The JSON file database suits one server and a few thousand photos. For more, swap the `db` object for Postgres/MongoDB and the photo folder for S3/Blob storage.
4. Pages use in-browser Babel and CDN scripts for simplicity. For stricter security, precompile the JSX and add a Content-Security-Policy.
5. Back up `data/` (database + photos). Delete it after the event per your retention policy.
