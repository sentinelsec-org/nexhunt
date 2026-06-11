import { app, BrowserWindow, dialog, ipcMain } from 'electron'
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

    const detail = data.notes
      ? `Release notes:\n${data.notes.slice(0, 400)}`
      : `A new version is available.`

    const { response } = await dialog.showMessageBox({
      type: 'info',
      title: 'NexHunt Update Available',
      message: `Version ${data.latest} is available (you have ${data.current})`,
      detail,
      buttons: data.mandatory ? ['Update now'] : ['Update now', 'Later'],
      defaultId: 0,
      cancelId: 1,
    })

    if (response === 0) {
      await applyUpdate()
    }
  } catch {
    // No update server / offline — silent
  }
}

async function applyUpdate(): Promise<void> {
  const win = mainWindow
  if (win) {
    win.webContents.send('update:applying')
  }
  try {
    const res = await fetch(`${BACKEND_BASE}/api/update/apply`, { method: 'POST' })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' })) as { detail: string }
      dialog.showErrorBox('Update failed', err.detail || 'Could not apply update.')
      return
    }
    const data = await res.json() as { staged: boolean; restart_required: boolean; version: string }
    if (data.staged && data.restart_required) {
      dialog.showMessageBox({
        type: 'info',
        title: 'Update ready',
        message: `NexHunt ${data.version} has been downloaded. The app will now restart.`,
        buttons: ['Restart'],
      }).then(() => {
        app.relaunch()
        app.quit()
      })
    }
  } catch {
    dialog.showErrorBox('Update failed', 'Could not reach the update service.')
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
