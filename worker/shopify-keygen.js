/**
 * NexHunt licensing Worker.
 *
 * Routes:
 *   POST /shopify/order-webhook       Shopify orders/paid -> mint keygen license -> email key
 *   GET  /admin/licenses              list licenses           (X-Admin-Token)
 *   POST /admin/licenses              create a comp license   (X-Admin-Token, body {email})
 *   POST /admin/licenses/:id/revoke   suspend a license       (X-Admin-Token)
 *
 * Secrets (wrangler secret put ...):
 *   KEYGEN_PRODUCT_TOKEN   keygen admin/product token (NEVER ships in the app)
 *   KEYGEN_ACCOUNT_ID      e.g. 23e2d8ec-6bc5-40e2-937e-44ffe818b610
 *   KEYGEN_POLICY_ID       e.g. b216c614-6942-42da-b044-a25fbceb2ed5
 *   SHOPIFY_WEBHOOK_SECRET Shopify webhook signing secret (admin-registered webhooks)
 *   WEBHOOK_URL_TOKEN      shared token in the webhook URL ?t=... (API-registered webhooks)
 *   ADMIN_TOKEN            shared secret for /admin/* endpoints
 *   PRO_PRODUCT_ID         (optional) Shopify product id to match the PRO line item
 *   RESEND_API_KEY         (optional) Resend API key to email the license
 *   MAIL_FROM              (optional) verified from address, e.g. "NexHunt <license@sentinelsec.online>"
 */

const KEYGEN_BASE = (env) => `https://api.keygen.sh/v1/accounts/${env.KEYGEN_ACCOUNT_ID}`;
const KG_HEADERS = (env) => ({
  Authorization: `Bearer ${env.KEYGEN_PRODUCT_TOKEN}`,
  Accept: "application/vnd.api+json",
  "Content-Type": "application/vnd.api+json",
});

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ── keygen ──────────────────────────────────────────────────────────────────
async function createLicense(env, email) {
  const body = {
    data: {
      type: "licenses",
      attributes: { name: `NexHunt PRO - ${email}`, metadata: { email } },
      relationships: {
        policy: { data: { type: "policies", id: env.KEYGEN_POLICY_ID } },
      },
    },
  };
  const resp = await fetch(`${KEYGEN_BASE(env)}/licenses`, {
    method: "POST",
    headers: KG_HEADERS(env),
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (!resp.ok) {
    const err = data?.errors?.[0];
    throw new Error(err?.detail || err?.title || `keygen create failed (${resp.status})`);
  }
  return data.data.attributes.key;
}

async function listLicenses(env) {
  const resp = await fetch(`${KEYGEN_BASE(env)}/licenses?limit=100`, {
    headers: KG_HEADERS(env),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(`keygen list failed (${resp.status})`);
  return (data.data || []).map((l) => ({
    id: l.id,
    key: l.attributes.key,
    name: l.attributes.name,
    status: l.attributes.status,
    created: l.attributes.created,
    expiry: l.attributes.expiry,
  }));
}

async function suspendLicense(env, id) {
  const resp = await fetch(`${KEYGEN_BASE(env)}/licenses/${id}/actions/suspend`, {
    method: "POST",
    headers: KG_HEADERS(env),
  });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data?.errors?.[0]?.detail || `keygen suspend failed (${resp.status})`);
  }
}

// ── email (optional, via Resend) ──────────────────────────────────────────────
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

async function emailKey(env, email, key) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) return false;
  const safeKey = escapeHtml(key);
  const downloadUrl = "https://github.com/sentinelsec-org/nexhunt/releases";
  const proUrl = "https://nexhunt.myshopify.com/products/nexhunt-pro";
  const supportEmail = "license@sentinelsec.online";
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: email,
      subject: "Your NexHunt PRO license key is ready",
      text:
        `Thanks for buying NexHunt PRO. Your lifetime PRO license is ready.\n\n` +
        `LICENSE KEY\n${key}\n\n` +
        `HOW TO ACTIVATE\n` +
        `1. Install or open NexHunt on Linux (Kali, Debian, or Ubuntu).\n` +
        `2. Open Settings -> License.\n` +
        `3. Paste the license key above and click Activate.\n` +
        `4. When the status changes to PRO, the Copilot, pipelines, bulk scans, JWT suite, GraphQL Auditor, and PRO reports are unlocked.\n\n` +
        `MOVING TO ANOTHER MACHINE\n` +
        `Open Settings -> License -> Deactivate on the old machine, then activate the same key on the new one.\n\n` +
        `Download / updates: ${downloadUrl}\n` +
        `Order page: ${proUrl}\n` +
        `Need help? Reply to this email or contact ${supportEmail}.\n\n` +
        `- NexHunt`,
      html:
        `<!doctype html>` +
        `<html><body style="margin:0;background:#09090b;color:#f4f4f5;font-family:Inter,Arial,sans-serif;">` +
        `<div style="max-width:640px;margin:0 auto;padding:32px 18px;">` +
        `<div style="border:1px solid #27272a;background:#111113;border-radius:12px;overflow:hidden;">` +
        `<div style="padding:24px 24px 18px;border-bottom:1px solid #27272a;background:#0f1110;">` +
        `<div style="font-size:12px;letter-spacing:1.8px;text-transform:uppercase;color:#f59e0b;font-weight:700;">NexHunt PRO</div>` +
        `<h1 style="margin:10px 0 8px;font-size:28px;line-height:1.12;color:#ffffff;">Your license key is ready</h1>` +
        `<p style="margin:0;color:#a1a1aa;font-size:15px;line-height:1.6;">Thanks for buying NexHunt PRO. Use this key to unlock the lifetime PRO workspace on Linux.</p>` +
        `</div>` +
        `<div style="padding:24px;">` +
        `<div style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:#22c55e;font-weight:700;margin-bottom:8px;">License key</div>` +
        `<div style="font-family:'JetBrains Mono','SFMono-Regular',Consolas,monospace;font-size:18px;line-height:1.5;color:#ffffff;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:16px;word-break:break-all;">${safeKey}</div>` +
        `<h2 style="font-size:18px;margin:26px 0 10px;color:#ffffff;">How to activate</h2>` +
        `<ol style="margin:0 0 22px;padding-left:22px;color:#d4d4d8;font-size:15px;line-height:1.7;">` +
        `<li>Install or open NexHunt on Linux: Kali, Debian, or Ubuntu.</li>` +
        `<li>Go to <strong>Settings -> License</strong>.</li>` +
        `<li>Paste the license key and click <strong>Activate</strong>.</li>` +
        `<li>When the badge changes to <strong>PRO</strong>, Copilot, pipelines, bulk scans, JWT, GraphQL, and PRO reports are unlocked.</li>` +
        `</ol>` +
        `<div style="border-top:1px solid #27272a;padding-top:18px;color:#a1a1aa;font-size:14px;line-height:1.6;">` +
        `<strong style="color:#f4f4f5;">Moving machines?</strong><br>` +
        `Open <strong>Settings -> License -> Deactivate</strong> on the old machine, then activate this same key on the new one.` +
        `</div>` +
        `<div style="margin-top:22px;display:flex;gap:10px;flex-wrap:wrap;">` +
        `<a href="${downloadUrl}" style="display:inline-block;background:#22c55e;color:#04130a;text-decoration:none;font-weight:700;border-radius:8px;padding:11px 14px;">Download NexHunt</a>` +
        `<a href="${proUrl}" style="display:inline-block;color:#f59e0b;text-decoration:none;font-weight:700;border:1px solid #3f3f46;border-radius:8px;padding:10px 13px;">Order page</a>` +
        `</div>` +
        `<p style="margin:22px 0 0;color:#71717a;font-size:13px;line-height:1.6;">Need help? Reply to this email or contact <a href="mailto:${supportEmail}" style="color:#f59e0b;">${supportEmail}</a>.</p>` +
        `</div></div></div></body></html>`,
    }),
  });
  return resp.ok;
}

// ── shopify HMAC ──────────────────────────────────────────────────────────────
async function verifyShopifyHmac(secret, rawBody, hmacHeader) {
  if (!hmacHeader) return false;
  const keyData = new TextEncoder().encode(secret);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, rawBody);
  const computed = btoa(String.fromCharCode(...new Uint8Array(sig)));
  // constant-time-ish compare
  if (computed.length !== hmacHeader.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ hmacHeader.charCodeAt(i);
  return diff === 0;
}

function isProOrder(env, order) {
  if (!env.PRO_PRODUCT_ID) return true; // not configured -> treat every paid order as PRO
  const want = String(env.PRO_PRODUCT_ID);
  return (order.line_items || []).some((li) => String(li.product_id) === want);
}

// ── router ──────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Shopify purchase webhook
    if (request.method === "POST" && path === "/shopify/order-webhook") {
      const raw = await request.arrayBuffer();
      // Accept if the URL carries the shared token (for API-registered webhooks)
      // OR a valid Shopify HMAC (for admin-registered webhooks with a signing secret).
      const urlToken = url.searchParams.get("t");
      const tokenOk = !!env.WEBHOOK_URL_TOKEN && urlToken === env.WEBHOOK_URL_TOKEN;
      const hmacOk = env.SHOPIFY_WEBHOOK_SECRET
        ? await verifyShopifyHmac(
            env.SHOPIFY_WEBHOOK_SECRET,
            raw,
            request.headers.get("X-Shopify-Hmac-Sha256")
          )
        : false;
      if (!tokenOk && !hmacOk) return json({ error: "unauthorized" }, 401);

      let order;
      try {
        order = JSON.parse(new TextDecoder().decode(raw));
      } catch {
        return json({ error: "bad json" }, 400);
      }
      const email = order.email || order.contact_email || order.customer?.email;
      if (!email) return json({ error: "no email" }, 400);
      if (!isProOrder(env, order)) return json({ ok: true, skipped: "not a PRO order" });

      try {
        const key = await createLicense(env, email);
        const emailed = await emailKey(env, email, key);
        // Always 200 so Shopify doesn't retry; surface delivery state in the body/logs.
        return json({ ok: true, emailed, key: emailed ? undefined : key });
      } catch (e) {
        console.error("mint failed", e.message);
        return json({ error: e.message }, 500);
      }
    }

    // Admin endpoints
    if (path.startsWith("/admin/")) {
      if (request.headers.get("X-Admin-Token") !== env.ADMIN_TOKEN) {
        return json({ error: "unauthorized" }, 401);
      }

      if (request.method === "GET" && path === "/admin/licenses") {
        try {
          return json({ licenses: await listLicenses(env) });
        } catch (e) {
          return json({ error: e.message }, 500);
        }
      }

      if (request.method === "POST" && path === "/admin/licenses") {
        const b = await request.json().catch(() => ({}));
        if (!b.email) return json({ error: "email required" }, 400);
        try {
          const key = await createLicense(env, b.email);
          return json({ ok: true, key });
        } catch (e) {
          return json({ error: e.message }, 500);
        }
      }

      const m = path.match(/^\/admin\/licenses\/([^/]+)\/revoke$/);
      if (request.method === "POST" && m) {
        try {
          await suspendLicense(env, m[1]);
          return json({ ok: true, revoked: m[1] });
        } catch (e) {
          return json({ error: e.message }, 500);
        }
      }
    }

    return json({ error: "not found" }, 404);
  },
};
