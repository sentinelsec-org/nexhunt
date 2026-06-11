import { create } from 'zustand'
import { api } from '@/api/http-client'

export interface LicenseStatus {
  tier: 'free' | 'pro'
  valid: boolean
  key_masked: string
  expires_at: string | null
  machine_id: string
  customer_email: string | null
  last_check: number | null
  offline_grace: boolean
  upgrade_url: string
}

interface LicenseState {
  status: LicenseStatus | null
  loading: boolean
  upgradeOpen: boolean
  upgradeFeature: string | null
  isPro: () => boolean
  fetchStatus: () => Promise<void>
  activate: (key: string) => Promise<LicenseStatus>
  deactivate: () => Promise<void>
  refresh: () => Promise<void>
  openUpgrade: (feature?: string) => void
  closeUpgrade: () => void
}

export const useLicenseStore = create<LicenseState>((set, get) => ({
  status: null,
  loading: false,
  upgradeOpen: false,
  upgradeFeature: null,
  isPro: () => get().status?.tier === 'pro',
  fetchStatus: async () => {
    set({ loading: true })
    try {
      const status = await api.get<LicenseStatus>('/api/license/status')
      set({ status, loading: false })
    } catch {
      set({ loading: false })
    }
  },
  activate: async (key: string) => {
    const status = await api.post<LicenseStatus>('/api/license/activate', { key })
    set({ status })
    return status
  },
  deactivate: async () => {
    const status = await api.post<LicenseStatus>('/api/license/deactivate', {})
    set({ status })
  },
  refresh: async () => {
    const status = await api.post<LicenseStatus>('/api/license/refresh', {})
    set({ status })
  },
  openUpgrade: (feature?: string) => set({ upgradeOpen: true, upgradeFeature: feature ?? null }),
  closeUpgrade: () => set({ upgradeOpen: false, upgradeFeature: null }),
}))
