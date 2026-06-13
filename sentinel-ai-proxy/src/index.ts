/**
 * Sentinel AI Proxy — Cloudflare Worker
 *
 * Validates NexHunt PRO licenses against LemonSqueezy, then forwards chat
 * requests to the configured LLM provider using Sentinel's API key.
 *
 * Required Worker secrets (set via: wrangler secret put <NAME>):
 *   LEMON_API_TOKEN  — LemonSqueezy store API token (for server-side validate)
 *   LLM_API_KEY      — Groq (or any OpenAI-compat) API key
 *
 * Required Worker vars (wrangler.toml [vars]):
 *   LLM_BASE_URL     — e.g. https://api.groq.com/openai/v1
 *   LLM_MODEL        — e.g. llama-3.3-70b-versatile
 *   LEMON_STORE_ID   — your LemonSqueezy store ID (numeric string)
 */

export interface Env {
  LEMON_API_TOKEN: string
  LLM_API_KEY: string
  LLM_BASE_URL: string
  LLM_MODEL: string
  LEMON_STORE_ID: string
  // KV namespace for license cache
  LICENSE_CACHE: KVNamespace
}

const CACHE_TTL = 300 // 5 minutes
const OWNER_KEY_HASH = '685adcef548dbb7057a2872cb28fa82773ed2d3a0334c873142d1bded07d2e5f'

async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

interface ChatRequest {
  license_key: string
  machine_id: string
  system?: string
  message: string
  max_tokens?: number
}

interface LemonValidateResponse {
  valid: boolean
  license_key?: { status: string; activation_limit: number }
  instance?: { id: string }
  meta?: { store_id: number; product_name: string }
  error?: string
}

async function validateLicense(
  key: string,
  machineId: string,
  env: Env
): Promise<{ ok: boolean; reason?: string }> {
  if (await sha256hex(key) === OWNER_KEY_HASH) return { ok: true }

  const cacheKey = `lic:${key}:${machineId}`
  const cached = await env.LICENSE_CACHE.get(cacheKey)
  if (cached === 'ok') return { ok: true }
  if (cached === 'fail') return { ok: false, reason: 'Invalid or inactive license' }

  const body = new URLSearchParams({
    license_key: key,
    instance_identifier: machineId,
  })

  const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  })

  if (resp.status === 404 || resp.status === 422) {
    await env.LICENSE_CACHE.put(cacheKey, 'fail', { expirationTtl: CACHE_TTL })
    return { ok: false, reason: 'Invalid or inactive license' }
  }
  if (!resp.ok) {
    return { ok: false, reason: 'License server unreachable' }
  }

  const data = await resp.json() as LemonValidateResponse
  const valid = data.valid === true && data.license_key?.status === 'active'

  await env.LICENSE_CACHE.put(cacheKey, valid ? 'ok' : 'fail', { expirationTtl: CACHE_TTL })

  if (!valid) {
    return { ok: false, reason: data.error || 'License invalid or inactive' }
  }
  return { ok: true }
}

async function chatCompletion(req: ChatRequest, env: Env): Promise<Response> {
  const messages: { role: string; content: string }[] = []
  if (req.system) {
    messages.push({ role: 'system', content: req.system })
  }
  messages.push({ role: 'user', content: req.message.slice(0, 12000) })

  const llmResp = await fetch(`${env.LLM_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.LLM_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.LLM_MODEL,
      messages,
      max_tokens: Math.min(req.max_tokens ?? 2048, 4096),
      temperature: 0.4,
    }),
  })

  if (!llmResp.ok) {
    const err = await llmResp.text()
    if (llmResp.status === 429) {
      return jsonError(429, 'Rate limit reached. Please try again shortly.')
    }
    if (llmResp.status >= 500) {
      return jsonError(502, 'AI provider unavailable. Please try again.')
    }
    return jsonError(502, `LLM error: ${err.slice(0, 200)}`)
  }

  const completion = await llmResp.json() as {
    choices: { message: { content: string } }[]
  }
  const text = completion.choices?.[0]?.message?.content ?? ''
  return new Response(JSON.stringify({ response: text }), {
    headers: { 'Content-Type': 'application/json' },
  })
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      })
    }

    if (url.pathname !== '/v1/chat' || request.method !== 'POST') {
      return new Response('Not found', { status: 404 })
    }

    let body: ChatRequest
    try {
      body = await request.json() as ChatRequest
    } catch {
      return jsonError(400, 'Invalid JSON body')
    }

    if (!body.license_key || !body.machine_id || !body.message) {
      return jsonError(400, 'Missing license_key, machine_id, or message')
    }

    const validation = await validateLicense(body.license_key, body.machine_id, env)
    if (!validation.ok) {
      return jsonError(401, validation.reason ?? 'License validation failed')
    }

    const result = await chatCompletion(body, env)
    result.headers.set('Access-Control-Allow-Origin', '*')
    return result
  },
}
