import { spawn, ChildProcess } from 'child_process'
import path from 'path'

export class PythonBridge {
  private proc: ChildProcess | null = null
  private port: number
  private restartCount = 0
  private maxRestarts = 3

  constructor(port: number) {
    this.port = port
  }

  async start(): Promise<void> {
    const backendDir = this.getBackendDir()
    const pythonPath = this.findPython()

    console.log(`Starting Python backend on port ${this.port}...`)
    console.log(`Backend dir: ${backendDir}`)
    console.log(`Python: ${pythonPath}`)

    this.proc = spawn(pythonPath, [
      '-m', 'uvicorn',
      'nexhunt.main:app',
      '--host', '127.0.0.1',
      '--port', String(this.port),
      '--log-level', 'info'
    ], {
      cwd: backendDir,
      env: {
        ...process.env,
        NEXHUNT_PORT: String(this.port),
        PYTHONUNBUFFERED: '1',
        // Ensure Go tools (katana, dalfox, nuclei...) and venv tools (xsstrike, arjun...) are reachable
        PATH: [
          `${process.env.HOME}/go/bin`,
          `${backendDir}/venv/bin`,
          process.env.PATH
        ].filter(Boolean).join(':')
      },
      stdio: ['ignore', 'pipe', 'pipe']
    })

    this.proc.stdout?.on('data', (data: Buffer) => {
      console.log(`[backend] ${data.toString().trim()}`)
    })

    this.proc.stderr?.on('data', (data: Buffer) => {
      console.error(`[backend] ${data.toString().trim()}`)
    })

    this.proc.on('exit', (code: number | null) => {
      console.log(`Python backend exited with code ${code}`)
      if (code !== 0 && this.restartCount < this.maxRestarts) {
        this.restartCount++
        console.log(`Restarting backend (attempt ${this.restartCount}/${this.maxRestarts})...`)
        setTimeout(() => this.start(), 2000)
      }
    })

    await this.waitForReady()
  }

  private getBackendDir(): string {
    // In development: backend/ is next to electron/
    // In production: resources/backend/
    const devPath = path.join(__dirname, '../../backend')
    const prodPath = path.join(process.resourcesPath || '', 'backend')

    try {
      require('fs').accessSync(devPath)
      return devPath
    } catch {
      return prodPath
    }
  }

  private findPython(): string {
    // Try venv first, then system python
    const venvPython = process.platform === 'win32'
      ? path.join(this.getBackendDir(), 'venv', 'Scripts', 'python.exe')
      : path.join(this.getBackendDir(), 'venv', 'bin', 'python')

    try {
      require('fs').accessSync(venvPython)
      return venvPython
    } catch {
      return process.platform === 'win32' ? 'python' : 'python3'
    }
  }

  private async waitForReady(timeout = 20000): Promise<void> {
    const start = Date.now()
    while (Date.now() - start < timeout) {
      try {
        const response = await fetch(`http://127.0.0.1:${this.port}/api/health`)
        if (response.ok) {
          this.restartCount = 0
          return
        }
      } catch {
        // Not ready yet
      }
      await new Promise(r => setTimeout(r, 300))
    }
    throw new Error(`Python backend did not start within ${timeout}ms`)
  }

  stop(): void {
    if (this.proc && !this.proc.killed) {
      this.maxRestarts = 0 // Prevent restart on intentional kill
      this.proc.kill('SIGTERM')
      setTimeout(() => {
        if (this.proc && !this.proc.killed) {
          this.proc.kill('SIGKILL')
        }
      }, 5000)
    }
  }
}
