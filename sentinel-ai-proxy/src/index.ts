/**
 * Sentinel AI Proxy — Cloudflare Worker
 *
 * Routes:
 *   POST /v1/chat          — validate PRO license, proxy chat to LLM
 *   POST /webhook/paddle   — receive Paddle transaction events, create Keygen licenses
 *
 * Required Worker secrets (wrangler secret put <NAME>):
 *   KEYGEN_PRODUCT_TOKEN   — Keygen product token (license creation)
 *   PADDLE_WEBHOOK_SECRET  — Paddle notification secret (pdl_ntfset_...)
 *   PADDLE_API_KEY         — Paddle API key (pdl_... — to fetch customer email)
 *   LLM_API_KEY            — Groq API key
 *   LEMON_API_TOKEN        — LemonSqueezy token (kept as fallback)
 *
 * Required Worker vars (wrangler.toml [vars]):
 *   LICENSE_PROVIDER       — "keygen" | "lemonsqueezy" | "gumroad"
 *   KEYGEN_ACCOUNT_ID      — Keygen account ID
 *   KEYGEN_POLICY_ID       — Keygen policy ID
 *   LLM_BASE_URL / LLM_MODEL
 *   LEMON_STORE_ID / GUMROAD_PRODUCT_ID (fallbacks)
 */

export interface Env {
  LICENSE_PROVIDER: string
  KEYGEN_ACCOUNT_ID: string
  KEYGEN_POLICY_ID: string
  KEYGEN_PRODUCT_TOKEN: string
  PADDLE_WEBHOOK_SECRET: string
  PADDLE_API_KEY: string
  LEMON_API_TOKEN: string
  LEMON_STORE_ID: string
  GUMROAD_PRODUCT_ID?: string
  LLM_API_KEY: string
  LLM_BASE_URL: string
  LLM_MODEL: string
  LICENSE_CACHE: KVNamespace
}

const CACHE_TTL = 300
const OWNER_KEY_HASH = '685adcef548dbb7057a2872cb28fa82773ed2d3a0334c873142d1bded07d2e5f'

async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── License validation ────────────────────────────────────────────────────────

interface ValidateResult { ok: boolean; reason?: string; cacheable: boolean }

async function validateLicense(key: string, machineId: string, env: Env): Promise<{ ok: boolean; reason?: string }> {
  if (await sha256hex(key) === OWNER_KEY_HASH) return { ok: true }

  const cacheKey = `lic:${key}:${machineId}`
  const cached = await env.LICENSE_CACHE.get(cacheKey)
  if (cached === 'ok') return { ok: true }
  if (cached === 'fail') return { ok: false, reason: 'Invalid or inactive license' }

  const provider = (env.LICENSE_PROVIDER || 'keygen').toLowerCase()
  let result: ValidateResult

  if (provider === 'keygen') {
    result = await validateKeygen(key, machineId, env)
  } else if (provider === 'gumroad') {
    result = await validateGumroad(key, env)
  } else {
    result = await validateLemon(key, machineId)
  }

  if (result.cacheable) {
    await env.LICENSE_CACHE.put(cacheKey, result.ok ? 'ok' : 'fail', { expirationTtl: CACHE_TTL })
  }
  return { ok: result.ok, reason: result.reason }
}

async function validateKeygen(key: string, machineId: string, env: Env): Promise<ValidateResult> {
  if (!env.KEYGEN_ACCOUNT_ID) return { ok: false, reason: 'Keygen not configured', cacheable: false }
  const resp = await fetch(
    `https://api.keygen.sh/v1/accounts/${env.KEYGEN_ACCOUNT_ID}/licenses/actions/validate-key`,
    {
      method: 'POST',
      headers: { 'Accept': 'application/vnd.api+json', 'Content-Type': 'application/vnd.api+json' },
      body: JSON.stringify({ meta: { key, scope: { fingerprint: machineId } } }),
    }
  )
  if (resp.status >= 500) return { ok: false, reason: 'License server unavailable', cacheable: false }
  if (resp.status === 404) return { ok: false, reason: 'Invalid license key', cacheable: true }
  const data = await resp.json() as { meta?: { valid?: boolean; code?: string }; errors?: { detail: string }[] }
  const code = data.meta?.code || ''
  // NO_MACHINES = valid key but machine not activated yet; app handles activation
  const valid = data.meta?.valid === true && (code === 'VALID' || code === 'NO_MACHINES')
  return {
    ok: valid,
    reason: valid ? undefined : (data.errors?.[0]?.detail || `License ${code.toLowerCase()}`),
    cacheable: code !== 'FINGERPRINT_SCOPE_MISMATCH',
  }
}

async function validateLemon(key: string, machineId: string): Promise<ValidateResult> {
  const body = new URLSearchParams({ license_key: key, instance_identifier: machineId })
  const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (resp.status === 404 || resp.status === 422) return { ok: false, reason: 'Invalid or inactive license', cacheable: true }
  if (!resp.ok) return { ok: false, reason: 'License server unreachable', cacheable: false }
  const data = await resp.json() as { valid?: boolean; license_key?: { status: string }; error?: string }
  const valid = data.valid === true && data.license_key?.status === 'active'
  return { ok: valid, reason: valid ? undefined : (data.error || 'License invalid'), cacheable: true }
}

async function validateGumroad(key: string, env: Env): Promise<ValidateResult> {
  if (!env.GUMROAD_PRODUCT_ID) return { ok: false, reason: 'Gumroad product not configured', cacheable: false }
  const body = new URLSearchParams({ product_id: env.GUMROAD_PRODUCT_ID, license_key: key, increment_uses_count: 'false' })
  const resp = await fetch('https://api.gumroad.com/v2/licenses/verify', {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (resp.status === 404) return { ok: false, reason: 'Invalid license key', cacheable: true }
  if (!resp.ok) return { ok: false, reason: 'License server unreachable', cacheable: false }
  const data = await resp.json() as { success?: boolean; purchase?: { refunded?: boolean; disputed?: boolean; chargebacked?: boolean }; message?: string }
  const p = data.purchase || {}
  const dead = p.refunded || p.disputed || p.chargebacked
  const valid = data.success === true && !dead
  return { ok: valid, reason: valid ? undefined : (data.message || 'License invalid'), cacheable: true }
}

// ── Keygen license creation ───────────────────────────────────────────────────

async function createKeygenLicense(email: string, env: Env): Promise<string> {
  const resp = await fetch(
    `https://api.keygen.sh/v1/accounts/${env.KEYGEN_ACCOUNT_ID}/licenses`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.KEYGEN_PRODUCT_TOKEN}`,
        'Accept': 'application/vnd.api+json',
        'Content-Type': 'application/vnd.api+json',
      },
      body: JSON.stringify({
        data: {
          type: 'licenses',
          attributes: { name: `NexHunt PRO - ${email}` },
          relationships: {
            policy: { data: { type: 'policies', id: env.KEYGEN_POLICY_ID } },
            user: { data: { type: 'users', attributes: { email } } },
          },
        },
      }),
    }
  )
  const data = await resp.json() as { data?: { attributes?: { key: string } }; errors?: { detail: string }[] }
  if (!resp.ok) throw new Error(data.errors?.[0]?.detail || 'Failed to create license')
  return data.data?.attributes?.key ?? ''
}

// ── Paddle webhook ────────────────────────────────────────────────────────────

async function verifyPaddleSignature(body: string, sig: string, secret: string): Promise<boolean> {
  // Paddle-Signature: ts=1234567890;h1=abc123...
  const parts = Object.fromEntries(sig.split(';').map(p => p.split('=')))
  const ts = parts['ts']
  const h1 = parts['h1']
  if (!ts || !h1) return false
  const payload = `${ts}:${body}`
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const sig_bytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))
  const computed = Array.from(new Uint8Array(sig_bytes)).map(b => b.toString(16).padStart(2, '0')).join('')
  return computed === h1
}

async function getPaddleCustomerEmail(customerId: string, env: Env): Promise<string> {
  if (!env.PADDLE_API_KEY || !customerId) return ''
  // Paddle Billing API — use sandbox URL during testing, production otherwise
  const baseUrl = env.PADDLE_API_KEY.includes('_sandbox_')
    ? 'https://sandbox-api.paddle.com'
    : 'https://api.paddle.com'
  const resp = await fetch(`${baseUrl}/customers/${customerId}`, {
    headers: { 'Authorization': `Bearer ${env.PADDLE_API_KEY}`, 'Content-Type': 'application/json' },
  })
  if (!resp.ok) return ''
  const data = await resp.json() as { data?: { email?: string } }
  return data.data?.email ?? ''
}

async function handlePaddleWebhook(request: Request, env: Env): Promise<Response> {
  const sig = request.headers.get('Paddle-Signature') || ''
  const body = await request.text()

  if (!env.PADDLE_WEBHOOK_SECRET) return new Response('Webhook not configured', { status: 500 })

  const valid = await verifyPaddleSignature(body, sig, env.PADDLE_WEBHOOK_SECRET)
  if (!valid) return new Response('Invalid signature', { status: 400 })

  let event: { event_type: string; data: Record<string, unknown> }
  try { event = JSON.parse(body) } catch { return new Response('Invalid JSON', { status: 400 }) }

  // Only process completed transactions
  if (event.event_type !== 'transaction.completed') {
    return new Response(JSON.stringify({ received: true }), { headers: { 'Content-Type': 'application/json' } })
  }

  const data = event.data as {
    id?: string
    customer_id?: string
    customer?: { email?: string }
    billing_details?: { email?: string }
    custom_data?: { email?: string }
  }

  // Try to get email from the event itself first, then fetch from API
  let email = data.customer?.email
    || data.billing_details?.email
    || data.custom_data?.email
    || ''

  if (!email && data.customer_id) {
    email = await getPaddleCustomerEmail(data.customer_id as string, env)
  }

  if (!email) {
    console.error('Paddle webhook: no customer email in transaction', data.id)
    return new Response(JSON.stringify({ received: true, warning: 'no email' }), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  try {
    const licenseKey = await createKeygenLicense(email, env)
    console.log(`License created for ${email}: ${licenseKey.slice(0, 8)}...`)
    return new Response(JSON.stringify({ received: true, created: true }), {
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    console.error('Failed to create Keygen license:', msg)
    return new Response(JSON.stringify({ received: true, error: msg }), {
      status: 200, // 200 so Paddle doesn't retry permanently
      headers: { 'Content-Type': 'application/json' },
    })
  }
}

// ── Chat completion ───────────────────────────────────────────────────────────

interface ChatRequest {
  license_key: string
  machine_id: string
  system?: string
  message: string
  max_tokens?: number
}

async function chatCompletion(req: ChatRequest, env: Env): Promise<Response> {
  const messages: { role: string; content: string }[] = []
  if (req.system) messages.push({ role: 'system', content: req.system })
  messages.push({ role: 'user', content: req.message.slice(0, 12000) })

  const llmResp = await fetch(`${env.LLM_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.LLM_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: env.LLM_MODEL,
      messages,
      max_tokens: Math.min(req.max_tokens ?? 2048, 4096),
      temperature: 0.4,
    }),
  })

  if (!llmResp.ok) {
    const err = await llmResp.text()
    if (llmResp.status === 429) return jsonError(429, 'Rate limit reached. Please try again shortly.')
    if (llmResp.status >= 500) return jsonError(502, 'AI provider unavailable.')
    return jsonError(502, `LLM error: ${err.slice(0, 200)}`)
  }

  const completion = await llmResp.json() as { choices: { message: { content: string } }[] }
  const text = completion.choices?.[0]?.message?.content ?? ''
  return new Response(JSON.stringify({ response: text }), { headers: { 'Content-Type': 'application/json' } })
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), { status, headers: { 'Content-Type': 'application/json' } })
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS })

    if (url.pathname === '/webhook/paddle' && request.method === 'POST') {
      return handlePaddleWebhook(request, env)
    }

    if (url.pathname !== '/v1/chat' || request.method !== 'POST') {
      return new Response('Not found', { status: 404 })
    }

    let body: ChatRequest
    try { body = await request.json() as ChatRequest }
    catch { return jsonError(400, 'Invalid JSON body') }

    if (!body.license_key || !body.machine_id || !body.message) {
      return jsonError(400, 'Missing license_key, machine_id, or message')
    }

    const validation = await validateLicense(body.license_key, body.machine_id, env)
    if (!validation.ok) return jsonError(401, validation.reason ?? 'License validation failed')

    const result = await chatCompletion(body, env)
    result.headers.set('Access-Control-Allow-Origin', '*')
    return result
  },
}
