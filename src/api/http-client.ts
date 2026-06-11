import { API_BASE } from '@/lib/constants'

const DEFAULT_TIMEOUT = 30000

class HttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'HttpError'
    this.status = status
  }
}

class HttpClient {
  private baseUrl: string

  constructor() {
    this.baseUrl = API_BASE
  }

  private async request(url: string, init: RequestInit, timeout = DEFAULT_TIMEOUT): Promise<Response> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    let res: Response
    try {
      res = await fetch(url, { ...init, signal: controller.signal })
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') {
        throw new HttpError(0, `Request timed out after ${timeout}ms`)
      }
      throw new HttpError(0, `Network error: ${(e as Error).message}`)
    } finally {
      clearTimeout(timer)
    }
    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      if (res.status === 402) {
        // PRO-gated endpoint: surface the upgrade modal instead of a raw error.
        let feature: string | undefined
        try { feature = JSON.parse(detail)?.detail?.feature } catch {}
        import('@/stores/license-store').then(({ useLicenseStore }) => {
          useLicenseStore.getState().openUpgrade(feature)
        })
        throw new HttpError(402, 'pro_required')
      }
      throw new HttpError(res.status, detail || `${res.status} ${res.statusText}`)
    }
    return res
  }

  async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(path, this.baseUrl)
    if (params) {
      Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v))
    }
    const res = await this.request(url.toString(), {})
    return res.json()
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    const res = await this.request(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    })
    return res.json()
  }

  async put<T>(path: string, body?: unknown): Promise<T> {
    const res = await this.request(`${this.baseUrl}${path}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    })
    return res.json()
  }

  async delete(path: string): Promise<void> {
    await this.request(`${this.baseUrl}${path}`, { method: 'DELETE' })
  }
}

export { HttpError }
export const api = new HttpClient()
