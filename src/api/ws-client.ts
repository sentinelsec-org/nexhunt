import { WS_BASE } from '@/lib/constants'
import type { WsMessage } from '@/types'

type MessageHandler = (data: unknown) => void

class WsClient {
  private ws: WebSocket | null = null
  private handlers: Map<string, Set<MessageHandler>> = new Map()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 1000
  private maxReconnectDelay = 30000
  private connected = false

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return

    try {
      this.ws = new WebSocket(`${WS_BASE}/ws`)

      this.ws.onopen = () => {
        console.log('[ws] Connected')
        this.connected = true
        this.reconnectDelay = 1000
      }

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const msg: WsMessage = JSON.parse(event.data)
          const channelHandlers = this.handlers.get(msg.channel)
          if (channelHandlers) {
            channelHandlers.forEach(handler => handler(msg.data))
          }
          // Also notify wildcard subscribers
          const allHandlers = this.handlers.get('*')
          if (allHandlers) {
            allHandlers.forEach(handler => handler(msg))
          }
        } catch (err) {
          console.error('[ws] Failed to parse message:', err)
        }
      }

      this.ws.onclose = () => {
        console.log('[ws] Disconnected')
        this.connected = false
        this.scheduleReconnect()
      }

      this.ws.onerror = (err) => {
        console.error('[ws] Error:', err)
      }
    } catch (err) {
      console.error('[ws] Connection failed:', err)
      this.scheduleReconnect()
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay)
      this.connect()
    }, this.reconnectDelay)
  }

  subscribe(channel: string, handler: MessageHandler): () => void {
    if (!this.handlers.has(channel)) {
      this.handlers.set(channel, new Set())
    }
    this.handlers.get(channel)!.add(handler)

    // Return unsubscribe function
    return () => {
      this.handlers.get(channel)?.delete(handler)
    }
  }

  send(data: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  isConnected(): boolean {
    return this.connected
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.ws?.close()
    this.ws = null
    this.connected = false
  }
}

export const wsClient = new WsClient()
