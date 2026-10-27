# AFL — Official Items & Ticket Requests

A working web application for browsing official AFL items and requesting them with tickets.

- **Discord sign-in** (OAuth2) — users see their Discord name and avatar
- **Item catalogue** — images, descriptions, categories, collections, availability, search, filters, sorting
- **Ticket requests** — signed-in users request items, track status, cancel open tickets
- **Private staff portal at `/staff`** — only authorised Discord user IDs can open it; staff accept / deny (with a reason) / update tickets
- **Owner controls** — manage staff access, catalogue items (incl. image upload), tickets, and read the audit log
- **In-site notifications** whenever a ticket is submitted, accepted, denied, updated, completed or reopened
- **Secure backend** — SQLite database, server-side sessions, CSRF protection, strict CSP, rate limiting, server-side role checks on every request

It has **zero npm dependencies**: just Node.js 22.13+ (uses the built-in `node:sqlite`, `http`, `crypto` and `fetch`). There is nothing to `npm install`.

---

## 1. Quick start

```bash
cp .env.example .env      # then fill it in (steps 2–4 below)
node --disable-warning=ExperimentalWarning server.js     # or: npm start
```

Open <http://localhost:3000>. The server prints warnings at start-up if anything important is missing from `.env`.

Run the automated test-suite (boots a throwaway database and exercises the real HTTP API — 75 checks):

```bash
npm test
```

## 2. Create the Discord application (OAuth2)

1. Go to <https://discord.com/developers/applications> → **New Application** → name it **AFL**.
2. Open **OAuth2** in the sidebar.
3. Copy the **Client ID** into `DISCORD_CLIENT_ID`.
4. Click **Reset Secret**, copy it into `DISCORD_CLIENT_SECRET` (keep it private).
5. Under **Redirects** click **Add Redirect** and enter exactly:
   - local: `http://localhost:3000/auth/discord/callback`
   - production: `https://YOUR-DOMAIN/auth/discord/callback`
   
   The redirect must match `BASE_URL` + `/auth/discord/callback` character for character. You can add both.
6. The site only requests the `identify` scope (username, avatar, ID) — no email, no servers.

## 3. Set the owner and staff Discord IDs

1. In Discord: **User Settings → Advanced → Developer Mode: on**.
2. Right-click a user (or yourself) → **Copy User ID** — an 17–20 digit number.
3. In `.env`:
   - `OWNER_DISCORD_ID=` your own ID. The owner always has full access and cannot be removed.
   - `STAFF_DISCORD_IDS=` optional comma-separated IDs, e.g. `111111111111111111,222222222222222222`.
4. After signing in as the owner, open **/staff → Staff members** to add or remove more staff by ID at any time. Changes apply immediately — roles are checked against the database on *every* request, so removing someone locks them out straight away.

| Role  | Can do |
|-------|--------|
| User  | Browse, request items, view/cancel own tickets, notifications |
| Staff | Everything above + open `/staff`, review the queue, accept / deny (reason required) / update status / message requesters. Cannot act on their *own* tickets |
| Owner | Everything above + manage staff, catalogue items, delete tickets, force any status, read audit log |

Anyone else who visits `/staff` gets a plain 404 (the portal's HTML and JavaScript are never sent to them).

## 4. Database

SQLite, created automatically at `DB_PATH` (default `data/afl.db`) on first run — no setup or migrations needed. It runs in WAL mode.

- **Back up** by copying the `data/` folder (stop the server, or use `sqlite3 data/afl.db ".backup backup.db"`).
- **Uploaded images** live in `UPLOAD_DIR` (default `uploads/`) — back that up too.
- On a host with an ephemeral filesystem you **must** mount a persistent volume at `data/` and `uploads/`, otherwise data is lost on every deploy.

## 5. Catalogue & branding — please read

**Catalogue.** On first run the catalogue is seeded from the 13 item images supplied with this project (`public/img/items/`): Old Boot, Cyan Skinny, Cyan KW9, Ballon D'or V1, Ballon D'or V23, Old Hat, Cyan Hat, Soda Hat, Old Goggles, Cyan Goggles, Old Mask, Gas Mask, Old Ball.

Names come from the file names. **Nothing else was invented**: descriptions only describe what is visible in each picture, availability is set to **"To be confirmed"**, and each row is flagged *Placeholder details*. Go to **/staff → Catalogue items** and set the real description, category, collection and availability for each item. Set `SEED_CATALOGUE=0` if you'd rather start empty and add items yourself.

**Logo.** No standalone logo file was supplied (only the badge as it appears printed on the items), so `public/img/logo.svg` is a clearly-labelled placeholder in the same style. **To use the official AFL logo, drop `logo.png` (or `logo.webp` / `logo.jpg` / `logo.svg`) into `public/img/`** — the site serves `/brand/logo` and automatically prefers a PNG/WebP/JPG over the placeholder. It is used in the header, footer, favicon and the staff portal.

All page titles, metadata and navigation say **AFL** only.

## 6. Deployment

Any host that can run Node 22.13+ works. Requirements for production:

1. **HTTPS.** Set `BASE_URL=https://your-domain` (this turns on `Secure` cookies and HSTS) and register the matching Discord redirect URI.
2. Set `TRUST_PROXY=1` if you're behind a reverse proxy / platform load balancer.
3. Persist `data/` and `uploads/`.
4. Keep `.env` out of git (already in `.gitignore`); on platforms set the variables in their dashboard instead.

### Docker

```bash
docker build -t afl .
docker run -d --name afl -p 3000:3000 --env-file .env \
  -v afl-data:/app/data -v afl-uploads:/app/uploads afl
```

### VPS with systemd + Caddy (HTTPS automatically)

```ini
# /etc/systemd/system/afl.service
[Service]
WorkingDirectory=/srv/afl
ExecStart=/usr/bin/node --disable-warning=ExperimentalWarning server.js
Restart=always
User=afl
EnvironmentFile=/srv/afl/.env
[Install]
WantedBy=multi-user.target
```

```
# Caddyfile
your-domain.com {
  reverse_proxy 127.0.0.1:3000
}
```

### Platforms (Render, Railway, Fly.io…)

Create a Node 22 web service, start command `node --disable-warning=ExperimentalWarning server.js`, add the `.env` values as environment variables, attach a persistent disk/volume at `/app/data` and `/app/uploads` (or point `DB_PATH` / `UPLOAD_DIR` at the volume), and set `TRUST_PROXY=1`.

## 7. Security notes

- **Sessions:** random 256-bit token in an `HttpOnly`, `SameSite=Lax` (and `Secure` over HTTPS) cookie; only its SHA-256 hash is stored server-side; a fresh session is issued on every login; sessions expire after `SESSION_DAYS`.
- **OAuth:** random `state` verified on callback; only the `identify` scope.
- **CSRF:** every state-changing request needs a per-session `X-CSRF-Token` header and a same-origin `Origin`.
- **Authorisation:** all `/api/staff/*` and `/api/owner/*` routes re-check role server-side per request; the `/staff` page and its scripts are only served to authorised users. Ticket decisions are race-safe (one decision wins) and staff can't process their own tickets.
- **Headers:** strict Content-Security-Policy (no inline scripts/styles), `nosniff`, frame denial, HSTS over HTTPS.
- **Input:** length-limited and validated; the UI renders user text with `textContent` only (no HTML injection); uploads are checked by file signature (PNG/JPEG/WebP, ≤ 4 MB) and given random names.
- **Abuse:** per-IP and per-user rate limits; caps on open tickets per user and duplicate requests.
- **Audit log:** logins, decisions, staff and catalogue changes, uploads and deletions are recorded with actor and IP.

## 8. Project layout

```
server.js        routes, ticket state machine, static serving
lib/             config, database schema, auth/sessions, HTTP helpers, catalogue seed
public/          the website (index.html, css/, js/, img/)
staff-ui/        the staff/owner portal UI — served only to authorised users
test/smoke.js    end-to-end API tests
```

Ticket lifecycle: `pending → accepted → in progress → completed`, with `denied` (reason required; can be reopened) and `cancelled` possible along the way. The owner can force any status.

## 9. Optional: Discord webhook

Set `DISCORD_WEBHOOK_URL` (Channel settings → Integrations → Webhooks) to post a short message to a staff channel whenever a new ticket arrives.
