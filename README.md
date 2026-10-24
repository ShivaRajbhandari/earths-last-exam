# Earth's Last Exam: landing page prototype

A prototype redesign of earthlastexam.ai by the Data-Driven EnviroLab (DDL). One static page plus a small sign-up backend.

- **Live prototype:** https://www.shivarajbhandari.com/earths-last-exam/ (noindex; remove the robots meta and the `data-prototype-banner` ribbon in `index.html` for production)
- **Sign-up admin ("CMS"):** https://ele-signups.shiva-a-rajbhandari.workers.dev/admin (password-protected)

## What's here

| Path | What it is |
|---|---|
| `index.html` | The whole landing page (HTML, CSS, JS in one file). Globe uses three.js r128 from cdnjs, same as the current site. |
| `assets/ddl-wordmark.png` | DDL wordmark, copied from datadrivenlab.org |
| `worker/src/index.js` | Cloudflare Worker: `POST /api/signup`, plus the admin dashboard (`/admin`), JSON list, CSV export, per-person status/notes and delete |
| `worker/migrations/0001_init.sql` | D1 table for sign-ups |
| `worker/wrangler.jsonc` | Worker config (D1 binding, allowed origins) |

## Placeholders to replace before launch

Look for the yellow dashed `[...]` text on the page: launch date, and privacy wording. Search `index.html` for `class="ph"`.

## Sign-up backend

Fields collected: name, email, affiliation, area of expertise (plus an optional free-text field when "Other"). Repeat sign-ups with the same email update the existing row. A hidden honeypot field and a per-network rate limit (10/hour, hashed IP) slow spam.

The admin page needs two Worker secrets: `ADMIN_PASSWORD` (the login) and `SESSION_SECRET` (random, signs the login cookie and hashes IPs). Set them in the Cloudflare dashboard (Workers > ele-signups > Settings > Variables and Secrets) or with `cf workers secrets update`. Rotating `ADMIN_PASSWORD` signs nobody out; rotating `SESSION_SECRET` does.

To change the site the form posts from, edit `ALLOWED_ORIGINS` in `worker/wrangler.jsonc` (and the Worker's variable in Cloudflare). To point the page at a different Worker, change `SIGNUP_ENDPOINT` near the bottom of `index.html`.

### Redeploying the Worker

```
cd worker
npm install
npx wrangler login      # once
npx wrangler deploy
```

Note: `wrangler deploy` re-sends `vars` from `wrangler.jsonc` and keeps existing secrets.

### Database

```
npx wrangler d1 migrations apply ele-signups --remote
```

Sign-up data contains personal information. Don't commit exports, and decide on retention and consent wording with DDL before launch.
