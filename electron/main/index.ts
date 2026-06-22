import { app, BrowserWindow, ipcMain } from 'electron'
import { spawn } from 'child_process'
import path from 'path'
import { PythonBridge } from './python-bridge'

const BACKEND_PORT = 17707
const BACKEND_BASE = `http://127.0.0.1:${BACKEND_PORT}`

let mainWindow: BrowserWindow | null = null
let pythonBridge: PythonBridge | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'NexHunt by Sentinel Security',
    backgroundColor: '#09090b',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  }

  mainWindow.on('closed', () => { mainWindow = null })
}

async function checkForUpdates(): Promise<void> {
  try {
    const res = await fetch(`${BACKEND_BASE}/api/update/check`)
    if (!res.ok) return
    const data = await res.json() as {
      update_available: boolean
      current: string
      latest: string
      notes: string
      mandatory: boolean
    }
    if (!data.update_available) return
    mainWindow?.webContents.send('update:available', data)
  } catch {
    // No update server / offline — silent
  }
}

function runPkexecAptInstall(debPath: string): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    const child = spawn('pkexec', ['apt', 'install', '-y', debPath])
    let stderr = ''
    child.stderr?.on('data', (d) => { stderr += d.toString() })
    child.on('error', (err) => resolve({ ok: false, error: err.message }))
    child.on('close', (code) => {
      if (code === 0) resolve({ ok: true })
      else resolve({ ok: false, error: stderr.trim() || `apt install exited with code ${code}` })
    })
  })
}

async function applyUpdate(): Promise<void> {
  const win = mainWindow
  win?.webContents.send('update:installing')
  try {
    const res = await fetch(`${BACKEND_BASE}/api/update/apply`, { method: 'POST' })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' })) as { detail: string }
      win?.webContents.send('update:error', err.detail || 'Could not apply update.')
      return
    }
    const data = await res.json() as {
      staged: boolean
      version: string
      deb_path?: string
      restart_required?: boolean
    }
    if (!data.staged) {
      win?.webContents.send('update:error', 'Already up to date.')
      return
    }

    if (data.deb_path) {
      const result = await runPkexecAptInstall(data.deb_path)
      if (!result.ok) {
        win?.webContents.send('update:error', result.error || 'Installation was cancelled or failed.')
        return
      }
      win?.webContents.send('update:done', data.version)
      setTimeout(() => { app.relaunch(); app.quit() }, 1500)
      return
    }

    if (data.restart_required) {
      win?.webContents.send('update:done', data.version)
      setTimeout(() => { app.relaunch(); app.quit() }, 1500)
    }
  } catch {
    win?.webContents.send('update:error', 'Could not reach the update service.')
  }
}

ipcMain.on('update:check', () => checkForUpdates())
ipcMain.on('update:apply', () => applyUpdate())

app.whenReady().then(async () => {
  pythonBridge = new PythonBridge(BACKEND_PORT)
  try {
    await pythonBridge.start()
  } catch (err) {
    console.error('Failed to start Python backend:', err)
  }

  createWindow()

  // Check for updates 8 seconds after startup (backend needs time to be ready)
  setTimeout(checkForUpdates, 8000)
  // Re-check every 4 hours
  setInterval(checkForUpdates, 4 * 60 * 60 * 1000)

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => { pythonBridge?.stop() })
