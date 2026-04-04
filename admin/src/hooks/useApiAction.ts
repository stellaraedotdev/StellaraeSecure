import { useCallback, useState } from 'react'

type UseApiActionOptions = {
  onError?: (error: unknown) => void
}

export function useApiAction(options: UseApiActionOptions = {}) {
  const { onError } = options
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = useCallback(
    async <T>(action: () => Promise<T>, mapError: (error: unknown) => string) => {
      setBusy(true)
      setError(null)
      try {
        return await action()
      } catch (apiError) {
        setError(mapError(apiError))
        onError?.(apiError)
        return null
      } finally {
        setBusy(false)
      }
    },
    [onError],
  )

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  return {
    busy,
    error,
    setError,
    clearError,
    run,
  }
}
