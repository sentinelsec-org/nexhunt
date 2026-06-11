// Single source of truth for which routes/actions are PRO (mirrors the backend gating).
// The backend is the real enforcement; this only drives UX (locks, upsell, ProGate).

// Whole pages that are PRO. Actions inside otherwise-free pages (bulk scans, pipelines,
// JWT, business logic) are gated per-button via ProBadge + the backend 402.
export const PRO_ROUTES: Record<string, string> = {
  '/copilot': 'AI Copilot',
}

// Feature keys used by ProBadge / openUpgrade across pages.
export const PRO_FEATURES = {
  copilot: 'AI Copilot',
  pipelines: 'Automated pipelines',
  nucleiBulk: 'Bulk Nuclei scanning',
  fullRecon: 'Full automated recon',
  endpointBulk: 'Bulk endpoint discovery',
  corsBulk: 'Bulk CORS scanning',
  intruder: 'Proxy Intruder',
  jwt: 'JWT attack suite',
  bizlogic: 'Business logic suite',
  reportExport: 'Professional report export',
  premiumTemplates: 'Premium templates and wordlists',
} as const

export type ProFeature = keyof typeof PRO_FEATURES
