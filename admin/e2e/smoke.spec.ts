import { expect, test, type Page } from '@playwright/test'

const HANDOFF_STATE_KEY = 'stellarae.auth.handoff.state'

function callbackUrl(permissions: string) {
  const identityTs = Math.floor(Date.now() / 1000)
  return `/auth/callback?account_id=staff-e2e&permissions=${encodeURIComponent(permissions)}&panel_session_id=panel-e2e&admin_key=admin-e2e&identity_ts=${identityTs}&identity_sig=sig-e2e&state=state-e2e`
}

async function seedHandoffState(page: Page) {
  await page.addInitScript(([key, value]) => {
    window.sessionStorage.setItem(key, value)
  }, [HANDOFF_STATE_KEY, 'state-e2e'])
}

test('panel smoke: validate session and load audit timeline', async ({ page }) => {
  await seedHandoffState(page)
  await page.route('**/api/panel/session/panel-e2e', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        active: true,
        session_id: 'panel-e2e',
      }),
    })
  })

  await page.route('**/api/admin/audit/events', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        events: [
          {
            id: 'evt-1',
            operation: 'panel.session.verify',
            target_type: 'panel_session',
            decision: 'allow',
          },
        ],
      }),
    })
  })

  await page.goto(
    callbackUrl('oauth.client.read panel.session.issue panel.audit.read oauth.token.revoke'),
  )
  await page.getByRole('link', { name: 'Panel Surface' }).click()

  await page.getByRole('button', { name: 'Validate Current Session' }).click()
  await expect(page.getByText('Active')).toBeVisible()

  await page.getByRole('button', { name: 'Load Audit Events' }).click()
  await expect(page.getByText('panel.session.verify')).toBeVisible()
})

test('admin smoke: fetch client and revoke token', async ({ page }) => {
  await seedHandoffState(page)
  await page.route('**/api/admin/clients/client-123', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        client_id: 'client-123',
        name: 'Operations Portal',
      }),
    })
  })

  await page.route('**/api/admin/tokens/revoke', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    })
  })

  await page.goto(callbackUrl('oauth.client.read oauth.token.revoke panel.session.issue'))

  await page.getByPlaceholder('oauth client id').fill('client-123')
  await page.getByRole('button', { name: 'Fetch Client' }).click()
  await expect(page.getByText('Operations Portal')).toBeVisible()

  await page.getByPlaceholder('access or refresh token').fill('token-e2e')
  await page.getByRole('button', { name: 'Revoke Token' }).click()
  await expect(page.getByText('Token revoked successfully.')).toBeVisible()
})

test('panel unauthorized path: 401 validation logs out to sign-in view', async ({ page }) => {
  await seedHandoffState(page)
  await page.route('**/api/panel/session/panel-e2e', async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'expired' }),
    })
  })

  await page.goto(callbackUrl('oauth.client.read panel.session.issue panel.audit.read'))
  await page.getByRole('link', { name: 'Panel Surface' }).click()
  await page.getByRole('button', { name: 'Validate Current Session' }).click()

  await expect(page.getByRole('heading', { name: 'Staff Sign-In' })).toBeVisible()
})

test('admin unauthorized path: 401 revoke logs out to sign-in view', async ({ page }) => {
  await seedHandoffState(page)
  await page.route('**/api/admin/tokens/revoke', async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'expired' }),
    })
  })

  await page.goto(callbackUrl('oauth.client.read oauth.token.revoke panel.session.issue'))
  await page.getByPlaceholder('access or refresh token').fill('token-e2e')
  await page.getByRole('button', { name: 'Revoke Token' }).click()

  await expect(page.getByRole('heading', { name: 'Staff Sign-In' })).toBeVisible()
})

test('panel forbidden path: 403 audit load keeps session and shows authorization message', async ({ page }) => {
  await seedHandoffState(page)
  await page.route('**/api/admin/audit/events', async (route) => {
    await route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'denied' }),
    })
  })

  await page.goto(callbackUrl('oauth.client.read panel.session.issue panel.audit.read'))
  await page.getByRole('link', { name: 'Panel Surface' }).click()
  await page.getByRole('button', { name: 'Load Audit Events' }).click()

  await expect(page.getByText(/Authorization failed\. Check permissions/i)).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Panel Surface' })).toBeVisible()
})

test('callback malformed path: missing state fails with validation reference', async ({ page }) => {
  await page.goto(
    '/auth/callback?account_id=staff-e2e&permissions=oauth.client.read&admin_key=admin-e2e&identity_ts=1912220999&identity_sig=sig-e2e',
  )

  await expect(page.getByRole('heading', { name: 'Sign-In Failed' })).toBeVisible()
  await expect(page.getByText('Ref: AUTH_CALLBACK_VALIDATION')).toBeVisible()
})