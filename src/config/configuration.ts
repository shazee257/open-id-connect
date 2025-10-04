export default () => ({
  port: parseInt(process.env.PORT ?? '3000', 10),
  databaseUrl: process.env.DATABASE_URL ?? '',
  oidc: {
    issuer: process.env.OIDC_ISSUER ?? 'http://localhost:3000',
    authCodeTtl: parseInt(process.env.AUTH_CODE_TTL ?? '300', 10),
    accessTokenTtl: parseInt(process.env.JWT_ACCESS_TTL ?? '300', 10),
    refreshTokenTtl: parseInt(process.env.JWT_REFRESH_TTL ?? String(60 * 60 * 24 * 14), 10),
    sessionTtl: parseInt(process.env.SESSION_TTL ?? '3600', 10),
    jwkRotationDays: parseInt(process.env.JWK_ROTATION_DAYS ?? '30', 10),
  },
});
