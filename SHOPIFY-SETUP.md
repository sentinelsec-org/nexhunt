# NexHunt on Shopify - setup guide

Goal: sell NexHunt PRO (one-time / lifetime) from the Shopify-hosted store at
`nexhunt.myshopify.com`, deliver a keygen license key automatically, and manage licenses.

The app already validates keygen keys (no app changes needed beyond the upgrade URL, already
done). Shopify only handles the storefront + checkout; the Worker mints + emails the key.

---

## 0. Prerequisites / cost
- Shopify **Basic** plan (~USD 39/mo, cheaper annually). The $5 Starter plan cannot host a
  full themed online store with custom pages - only buy buttons. We need the full store.
- Shopify store `nexhunt.myshopify.com`.
- keygen.sh account (already configured): account `23e2d8ec-6bc5-40e2-937e-44ffe818b610`,
  policy `b216c614-6942-42da-b044-a25fbceb2ed5`.
- Your existing Cloudflare Worker for the webhook (code in `prod/worker/`).

---

## 1. keygen - get the product token (one time)
1. keygen.sh -> Tokens -> create a **Product** token (or admin token) for NexHunt.
2. Keep it secret. It goes into the Worker only (step 4), never into the app.
3. Confirm the **policy** generates keys on license creation and allows the machine
   activation limit you want (e.g. 2 machines). Set this on the policy in keygen.

You can already **view / revoke / create** licenses from the keygen.sh dashboard today.

---

## 2. Shopify - create the store and product
1. Sign up at shopify.com, create the store.
2. Products -> Add product:
   - Title: `NexHunt PRO - Lifetime`
   - Description: see copy below.
   - Price: set your price (one-time).
   - **Uncheck "This is a physical product"** (digital - no shipping).
   - Inventory: untrack quantity (unlimited).
   - Save. Note the product handle -> URL becomes
     `https://nexhunt.myshopify.com/products/nexhunt-pro` (matches the app's upgrade URL).
3. Settings -> Checkout: enable guest checkout (buyers shouldn't need an account).
4. Settings -> Payments: connect Shopify Payments and/or PayPal. (MANUAL, needs your details.)

---

## 3. Shopify - build the site (theme + pages)
Use a free theme (Dawn) and restyle dark/minimal to match the current page. Build these,
using the ready copy in section 7:
- **Home**: hero + CTAs ("Free download" -> GitHub releases, "Get PRO" -> product page),
  the 5-phase workflow, feature grid, a screenshot, install snippet.
- **Pricing** page (`/pages/pricing`): Free vs PRO comparison table.
- **Install** page (`/pages/install`): the curl command + requirements.
- **Product** page: the buy button (auto-created with the product).
- Footer: GitHub, Releases, Issues, Sentinel Security.
- Languages: add ES locale (Shopify Markets/Translate) - keep the EN/ES parity of the app.

DNS: no custom product domain is required now. The public store is
`https://nexhunt.myshopify.com`.

---

## 4. Cloudflare Worker - deploy the licensing webhook
Code: `prod/worker/shopify-keygen.js` (+ `wrangler.toml`).

```
cd prod/worker
wrangler secret put KEYGEN_PRODUCT_TOKEN     # from step 1
wrangler secret put KEYGEN_ACCOUNT_ID        # 23e2d8ec-6bc5-40e2-937e-44ffe818b610
wrangler secret put KEYGEN_POLICY_ID         # b216c614-6942-42da-b044-a25fbceb2ed5
wrangler secret put SHOPIFY_WEBHOOK_SECRET   # from step 5
wrangler secret put ADMIN_TOKEN              # invent a long random string
wrangler secret put PRO_PRODUCT_ID           # optional - the Shopify product id
wrangler secret put RESEND_API_KEY           # optional - email delivery
wrangler secret put MAIL_FROM                # "NexHunt <license@sentinelsec.online>" after verifying sentinelsec.online in Resend
wrangler deploy
```

Email: if you skip Resend, the Worker still mints the key and returns it in the webhook
response (visible in Shopify's webhook log) - but for real delivery, either set up Resend
(free tier, verify the domain) or rely on a manual email per order at first.

---

## 5. Shopify - register the webhook
Settings -> Notifications -> Webhooks -> Create webhook:
- Event: **Order payment** (`orders/paid`)
- Format: JSON
- URL: `https://<your-worker-domain>/shopify/order-webhook`
- Copy the **signing secret** Shopify shows -> that's `SHOPIFY_WEBHOOK_SECRET` (step 4).

---

## 6. Managing licenses (view / revoke / create)
Two ways:
- **keygen.sh dashboard**: list, suspend (revoke), and create licenses by hand.
- **Worker admin API** (set `ADMIN_TOKEN` first):
  ```
  # list
  curl -H "X-Admin-Token: $TOKEN" https://<worker>/admin/licenses
  # create a comp/free PRO key
  curl -X POST -H "X-Admin-Token: $TOKEN" -H 'Content-Type: application/json' \
       -d '{"email":"friend@example.com"}' https://<worker>/admin/licenses
  # revoke
  curl -X POST -H "X-Admin-Token: $TOKEN" https://<worker>/admin/licenses/<id>/revoke
  ```
A revoked (suspended) key drops the app to Free on its next re-validation (within
`license_recheck_hours`, or immediately via Settings -> License -> Refresh).

---

## 7. Ready-to-paste copy (improve as you like)

### Product / hero description
> **NexHunt - the complete attack toolkit for bug bounty hunters.**
> Automated recon-to-exploitation on your own Linux box. 20+ integrated tools, a unified
> findings database, an HTTP proxy, and an AI copilot that actually analyzes your target.

### 5-phase workflow
1. **Reconnaissance** - subdomain enum, host probing, port scanning, crawling, parameter discovery (subfinder, amass, httpx, nmap, katana, gau, arjun).
2. **Vulnerability scanning** - 8,000+ Nuclei templates, CVE correlation, directory brute-force (nuclei, ffuf, nikto, gobuster, dirsearch).
3. **Exploitation** - SQLi, XSS, command injection, SSRF, JWT attacks.
4. **Proxy & reporting** - traffic capture, site mapping, fuzzing, AI report generation.
5. **AI copilot** - active pentest assistant: investigates URLs, reads findings, suggests exact commands.

### Pricing - Free vs PRO
**Free ($0)**
- Individual recon stages (subfinder, amass, httpx, Nmap Advanced, katana, gau, arjun)
- Single-target scanning (nuclei, ffuf, nikto, gobuster, dirsearch)
- Proxy: capture, repeater, site map, Intruder
- Single-target exploitation
- Findings database & projects
- WordPress, credential brute force, XSS pipeline, CORS, 403 bypass

**PRO - lifetime, one-time** (everything in Free, plus)
- AI Copilot: active attack-surface analysis + report generation
- Advanced SQLi / JS Secrets / full recon chains (with crawl caching across pipelines)
- Bulk scanning across all discovered hosts
- 10 JWT attack techniques with guidance
- GraphQL Auditor and Repository Intelligence
- Priority support

### Install snippet (copy-to-clipboard)
> Requirements: Linux (Kali / Debian / Ubuntu), Python 3.10+, ~2GB disk, internet.
> ```
> curl -fsSL https://github.com/sentinelsec-org/nexhunt/releases/download/v1.2.0/nexhunt-1.2.0.tar.gz | tar xz && sudo bash install.sh|> curl -fsSL https://github.com/sentinelsec-org/nexhunt/releases/download/v1.2.0/nexhunt-1.2.0.tar.gz | tar xz && sudo bash install.sh
> ```
> (point this at your real installer / GitHub releases)

### CTAs
- **Free download** -> GitHub releases: `https://github.com/sentinelsec-org/nexhunt/releases`
- **Get PRO** -> `https://nexhunt.myshopify.com/products/nexhunt-pro`

---

## 8. End-to-end test
1. keygen dashboard: create a test license, suspend it, confirm both work.
2. Worker: `curl` the webhook with a sample `orders/paid` payload + a valid HMAC; confirm a
   license appears in keygen (and the email arrives if Resend is set).
3. App: paste the key in Settings -> License -> Activate. Confirm PRO unlocks
   (`GET /api/license/status` -> `tier: "pro"`) and a PRO feature opens.
4. Revoke via admin/dashboard -> Settings -> License -> Refresh -> confirm it drops to Free.
5. Shopify test-mode order -> confirm the whole chain end to end.

## Day-1 fallback (sell before the Worker/email is wired)
Create keys in the keygen dashboard and email them manually per order. Same in-app
activation. Wire the Worker for automation afterward.
