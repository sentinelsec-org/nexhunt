import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
    build: {
      outDir: 'out/main',
      rollupOptions: {
        input: path.resolve(__dirname, 'electron/main/index.ts'),
        external: ['electron']
      }
    }
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    build: {
      outDir: 'out/preload',
      rollupOptions: {
        input: path.resolve(__dirname, 'electron/preload/index.ts'),
        external: ['electron']
      }
    }
  },
  renderer: {
    root: '.',
    build: {
      outDir: 'out/renderer',
      rollupOptions: {
        input: { index: path.resolve(__dirname, 'index.html') }
      }
    },
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: { '@': path.resolve(__dirname, 'src') }
    }
  }
})
