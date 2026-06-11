import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

export function getMethodColor(method: string): string {
  const colors: Record<string, string> = {
    GET: 'text-green-500',
    POST: 'text-blue-500',
    PUT: 'text-amber-500',
    DELETE: 'text-red-500',
    PATCH: 'text-purple-500',
    OPTIONS: 'text-zinc-500',
    HEAD: 'text-zinc-400'
  }
  return colors[method.toUpperCase()] || 'text-zinc-400'
}

export function getStatusColor(status: number): string {
  if (status >= 200 && status < 300) return 'text-green-500'
  if (status >= 300 && status < 400) return 'text-blue-400'
  if (status >= 400 && status < 500) return 'text-amber-500'
  if (status >= 500) return 'text-red-500'
  return 'text-zinc-400'
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-red-500 bg-red-500/10',
    high: 'text-orange-500 bg-orange-500/10',
    medium: 'text-yellow-500 bg-yellow-500/10',
    low: 'text-blue-500 bg-blue-500/10',
    info: 'text-zinc-400 bg-zinc-500/10'
  }
  return colors[severity] || 'text-zinc-400'
}
