import { Component, type ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: unknown) {
    console.error('Page crashed:', error, info)
  }

  reset = () => this.setState({ error: null })

  render() {
    if (this.state.error) {
      return (
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="max-w-md text-center">
            <div className="text-red-400 text-lg font-semibold mb-2">Something went wrong</div>
            <pre className="text-xs text-zinc-500 bg-zinc-900 rounded p-3 overflow-auto text-left mb-4">
              {this.state.error.message}
            </pre>
            <button
              onClick={this.reset}
              className="px-4 py-2 rounded-md bg-zinc-800 hover:bg-zinc-700 text-sm text-zinc-200"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
