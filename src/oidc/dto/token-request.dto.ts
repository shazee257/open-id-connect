import { IsIn, IsNotEmpty, IsOptional, IsString } from 'class-validator';

const SUPPORTED_GRANTS = ['authorization_code', 'refresh_token', 'client_credentials'] as const;

export type SupportedGrant = (typeof SUPPORTED_GRANTS)[number];

export class TokenRequestDto {
  @IsString()
  @IsIn(SUPPORTED_GRANTS as unknown as string[])
  grant_type!: SupportedGrant;

  @IsOptional()
  @IsString()
  code?: string;

  @IsOptional()
  @IsString()
  redirect_uri?: string;

  @IsOptional()
  @IsString()
  code_verifier?: string;

  @IsOptional()
  @IsString()
  refresh_token?: string;

  @IsOptional()
  @IsString()
  scope?: string;

  @IsOptional()
  @IsString()
  client_id?: string;

  @IsOptional()
  @IsString()
  client_secret?: string;
}
