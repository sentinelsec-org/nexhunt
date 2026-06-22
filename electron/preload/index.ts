import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('nexhunt', {
  platform: process.platform,
  versions: {
    node: process.versions.node,
    chrome: process.versions.chrome,
    electron: process.versions.electron
  },
  update: {
    apply: () => ipcRenderer.send('update:apply'),
    onAvailable: (cb: (data: { current: string; latest: string; notes: string; mandatory: boolean }) => void) => {
      const handler = (_e: unknown, data: any) => cb(data)
      ipcRenderer.on('update:available', handler)
      return () => ipcRenderer.removeListener('update:available', handler)
    },
    onInstalling: (cb: () => void) => {
      const handler = () => cb()
      ipcRenderer.on('update:installing', handler)
      return () => ipcRenderer.removeListener('update:installing', handler)
    },
    onDone: (cb: (version: string) => void) => {
      const handler = (_e: unknown, version: string) => cb(version)
      ipcRenderer.on('update:done', handler)
      return () => ipcRenderer.removeListener('update:done', handler)
    },
    onError: (cb: (message: string) => void) => {
      const handler = (_e: unknown, message: string) => cb(message)
      ipcRenderer.on('update:error', handler)
      return () => ipcRenderer.removeListener('update:error', handler)
    }
  }
})
