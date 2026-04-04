import { act, renderHook } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '../lib/api'
import { useApiAction } from './useApiAction'

describe('useApiAction', () => {
  it('sets busy and returns success result', async () => {
    const { result } = renderHook(() => useApiAction())

    let value: number | null = null
    await act(async () => {
      value = await result.current.run(async () => 42, () => 'error')
    })

    expect(value).toBe(42)
    expect(result.current.busy).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('captures mapped error and invokes onError callback', async () => {
    const onError = vi.fn()
    const { result } = renderHook(() => useApiAction({ onError }))

    const failure = new ApiError(401, 'bad auth', 'corr-401')

    let value: string | null = 'unset'
    await act(async () => {
      value = await result.current.run(
        async () => {
          throw failure
        },
        () => 'Mapped 401 message',
      )
    })

    expect(value).toBeNull()
    expect(result.current.error).toBe('Mapped 401 message')
    expect(onError).toHaveBeenCalledTimes(1)
    expect(onError).toHaveBeenCalledWith(failure)
  })
})
