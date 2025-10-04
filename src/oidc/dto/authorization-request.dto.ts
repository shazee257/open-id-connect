import { Transform } from 'class-transformer';
import { IsIn, IsNotEmpty, IsOptional, IsString, ValidateIf } from 'class-validator';

export class AuthorizationRequestDto {
  @IsString()
  @IsIn(['code'])
  response_type!: string;

  @IsString()
  @IsNotEmpty()
  client_id!: string;

  @IsString()
  @IsNotEmpty()
  redirect_uri!: string;

  @Transform(({ value }) =>
    typeof value === 'string'
      ? value
        .split(/[\s+]+/)
        .map((segment: string) => segment.trim())
        .filter(Boolean)
      : [],
  )
  scope: string[] = [];

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  nonce?: string;

  @IsOptional()
  @IsString()
  code_challenge?: string;

  @ValidateIf((o) => o.code_challenge)
  @IsString()
  @IsIn(['plain', 'S256', 's256'])
  code_challenge_method?: string;

  @IsOptional()
  @IsString()
  prompt?: string;

  @IsOptional()
  @IsString()
  session_id?: string;
}
