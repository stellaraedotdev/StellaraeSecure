export const appConfig = {
  oauth2BaseUrl:
    import.meta.env.VITE_OAUTH2_API_BASE_URL ?? 'http://localhost:4000',
  staffdbBaseUrl:
    import.meta.env.VITE_STAFFDB_API_BASE_URL ?? 'http://localhost:3000',
  authHandoffStartUrl: import.meta.env.VITE_AUTH_HANDOFF_START_URL ?? '',
  allowBootstrapLogin: import.meta.env.VITE_ALLOW_BOOTSTRAP_LOGIN === 'true',
  authHandoffRequireState: import.meta.env.VITE_AUTH_HANDOFF_REQUIRE_STATE !== 'false',
  authHandoffMaxSkewSeconds: Number(import.meta.env.VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS ?? 300),
}
