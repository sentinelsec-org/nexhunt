// Parses a raw HTTP request (or a bare header block) and extracts the auth-relevant
// cookies and headers for the Session panel, dropping analytics/tracking noise.

// Cookie names that are analytics/tracking/consent — dropped unless their value is a JWT.
const TRACKING_COOKIE = /^(_ga(_|$)|_gid$|_gat|_gcl(_|$)|_fbp$|_fbc$|__utm|_clck$|_clsk$|_hj|ajs_|mp_|amplitude|optimizely|intercom|hubspot|mixpanel|_pk_|_hp2|_uetsid$|_uetvid$|__gads$|__gpi$|__eoi$|fccdcf$|fcnec$|_pin_unauth$|test_cookie$|^ide$|locale$|nmstat$|_scid|_tt_|_rdt|_dc_gtm|_uetmsclkid)/i

// Standard browser/request headers that are never auth.
const SKIP_HEADER = new Set([
  'host', 'connection', 'content-length', 'cache-control', 'pragma', 'upgrade-insecure-requests',
  'user-agent', 'accept', 'accept-encoding', 'accept-language', 'accept-charset', 'referer', 'origin', 'dnt',
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-platform-version',
  'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list',
  'sec-ch-ua-model', 'priority', 'te', 'content-type', 'if-none-match', 'if-modified-since', 'range', 'cookie',
])

function isJwt(v: string): boolean {
  return /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+$/.test(v)
}

export interface ParsedSession {
  cookies: string
  headers: string
  keptCookies: string[]
  droppedCookies: string[]
  keptHeaders: string[]
}

export function parseRequestForSession(raw: string): ParsedSession {
  const lines = raw.replace(/\r/g, '').split('\n')
  let cookieValue = ''
  const headerLines: string[] = []

  for (const line of lines) {
    if (line.startsWith(':')) continue // HTTP/2 pseudo-headers
    const idx = line.indexOf(':')
    if (idx === -1) continue
    const name = line.slice(0, idx).trim()
    const value = line.slice(idx + 1).trim()
    if (!name || !value || name.includes(' ')) continue
    const lname = name.toLowerCase()
    if (lname === 'cookie') { cookieValue = value; continue }
    if (SKIP_HEADER.has(lname)) continue
    headerLines.push(`${name}: ${value}`)
  }

  // Cookie pairs are separated by "; " (standard) or ", " (some captures). A comma/semicolon
  // inside a value (e.g. JSON) has no following space, so this split keeps values intact.
  const rawCookies = cookieValue ? cookieValue.split(/[;,]\s+/) : []
  const kept: string[] = []
  const dropped: string[] = []
  for (const c of rawCookies) {
    const eq = c.indexOf('=')
    if (eq === -1) continue
    const cname = c.slice(0, eq).trim()
    const cval = c.slice(eq + 1).trim()
    if (!cname) continue
    if (TRACKING_COOKIE.test(cname) && !isJwt(cval)) { dropped.push(cname); continue }
    kept.push(`${cname}=${cval}`)
  }

  return {
    cookies: kept.join('; '),
    headers: headerLines.join('\n'),
    keptCookies: kept.map(c => c.slice(0, c.indexOf('='))),
    droppedCookies: dropped,
    keptHeaders: headerLines.map(h => h.slice(0, h.indexOf(':'))),
  }
}
