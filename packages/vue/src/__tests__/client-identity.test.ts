import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultClient } from '../client'

// Mock global fetch
const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function errorResponse(error: string, status: number) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('VaultClient — Identity', () => {
  let client: VaultClient

  beforeEach(() => {
    client = new VaultClient('https://vault42.example.com')
    client.accessToken = 'test-token'
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('getIdentity', () => {
    it('fetches identity profile', async () => {
      const identity = {
        given_name: 'Jane',
        family_name: 'Doe',
        country: 'US',
        date_of_birth: '1990-05-15',
        sex: 'female',
        updated_at: '2026-02-24T10:00:00Z',
      }
      mockFetch.mockResolvedValueOnce(jsonResponse(identity))

      const result = await client.getIdentity()

      expect(result).toEqual(identity)
      expect(mockFetch).toHaveBeenCalledOnce()
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/identity')
      expect(init.method).toBe('GET')
      expect(init.headers.Authorization).toBe('Bearer test-token')
    })

    it('fetches identity with billing', async () => {
      const identity = {
        given_name: 'Jane',
        billing: {
          address_line_1: '123 Main St',
          city: 'Springfield',
          country: 'US',
        },
        updated_at: '2026-02-24T10:00:00Z',
      }
      mockFetch.mockResolvedValueOnce(jsonResponse(identity))

      const result = await client.getIdentity()
      expect(result.billing?.address_line_1).toBe('123 Main St')
    })

    it('throws on 404 not found', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('identity_not_found', 404))

      await expect(client.getIdentity()).rejects.toMatchObject({
        code: 'identity_not_found',
        status: 404,
      })
    })

    it('throws on 500 server error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('internal_error', 500))

      await expect(client.getIdentity()).rejects.toMatchObject({
        code: 'internal_error',
        status: 500,
      })
    })
  })

  describe('putIdentity', () => {
    it('upserts identity profile', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'updated' }))

      const result = await client.putIdentity({
        given_name: 'Jane',
        family_name: 'Doe',
        country: 'US',
      })

      expect(result.status).toBe('updated')
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/identity')
      expect(init.method).toBe('PUT')
      expect(JSON.parse(init.body)).toEqual({
        given_name: 'Jane',
        family_name: 'Doe',
        country: 'US',
      })
    })

    it('sends billing data', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'updated' }))

      await client.putIdentity({
        given_name: 'Jane',
        billing: { address_line_1: '123 Main St', country: 'US' },
      })

      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body.billing.address_line_1).toBe('123 Main St')
    })

    it('throws on 400 invalid_country', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_country', 400))

      await expect(
        client.putIdentity({ country: 'XX' }),
      ).rejects.toMatchObject({ code: 'invalid_country', status: 400 })
    })

    it('throws on 400 invalid_date_of_birth', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse('invalid_date_of_birth', 400))

      await expect(
        client.putIdentity({ date_of_birth: '3000-01-01' }),
      ).rejects.toMatchObject({ code: 'invalid_date_of_birth' })
    })
  })

  describe('deleteIdentity', () => {
    it('deletes identity profile', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: 'deleted' }))

      const result = await client.deleteIdentity()

      expect(result.status).toBe('deleted')
      const [url, init] = mockFetch.mock.calls[0]
      expect(url).toBe('https://vault42.example.com/user/identity')
      expect(init.method).toBe('DELETE')
    })

    it('throws on 401 unauthorized', async () => {
      // Disable auto-refresh by clearing access token scenario
      client.accessToken = null
      mockFetch.mockResolvedValueOnce(errorResponse('unauthorized', 401))

      await expect(client.deleteIdentity()).rejects.toMatchObject({
        code: 'unauthorized',
        status: 401,
      })
    })
  })
})
