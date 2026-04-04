type HttpMethod = 'GET' | 'POST' | 'DELETE' | 'PATCH' | 'PUT'

type RequestOptions = {
  method?: HttpMethod
  headers?: Record<string, string>
  body?: unknown
}

export class ApiError extends Error {
  status: number
  responseText: string
  correlationId: string

  constructor(status: number, responseText: string, correlationId: string) {
    super(`HTTP ${status}: ${responseText || 'No response text'}`)
    this.name = 'ApiError'
    this.status = status
    this.responseText = responseText
    this.correlationId = correlationId
  }
}

export async function requestJson<T>(url: string, options: RequestOptions = {}) {
  const correlationId =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random()}`

  const response = await fetch(url, {
    method: options.method ?? 'GET',
    headers: {
      'content-type': 'application/json',
      'x-correlation-id': correlationId,
      ...options.headers,
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  })

  if (!response.ok) {
    const text = await response.text()
    throw new ApiError(response.status, text || response.statusText, correlationId)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}
