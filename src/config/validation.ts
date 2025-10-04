import * as Joi from 'joi';

export const validationSchema = Joi.object({
  DATABASE_URL: Joi.string().uri({ scheme: ['postgresql'] }).required(),
  OIDC_ISSUER: Joi.string().uri().default('http://localhost:3000'),
  AUTH_CODE_TTL: Joi.number().integer().min(60).default(300),
  JWT_ACCESS_TTL: Joi.number().integer().min(60).default(300),
  JWT_REFRESH_TTL: Joi.number().integer().min(300).default(60 * 60 * 24 * 14),
  SESSION_TTL: Joi.number().integer().min(300).default(3600),
  JWK_ROTATION_DAYS: Joi.number().integer().min(1).default(30),
  PORT: Joi.number().integer().min(1).max(65535).default(3000),
});
